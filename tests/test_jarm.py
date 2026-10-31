"""JARM tests: packet construction and ServerHello parsing, both offline.

The live behaviour was validated separately against real hosts; these tests pin
the two things that broke during development and would break silently again:

* a TLS 1.3 probe without ``key_share`` is rejected with alert 109 and measures
  nothing;
* reading fixed byte offsets out of a ServerHello reported ``0000`` for every
  server, making all fingerprints identical.
"""

from __future__ import annotations

import pytest

from origintrace import jarm


# ── packet construction ─────────────────────────────────────────────────────


@pytest.mark.parametrize("version,ciphers,order", [
    ("1.3", "ALL", "FORWARD"),
    ("1.2", "NO1.3", "REVERSE"),
    ("1.1", "ALL", "TOP_HALF"),
    ("1.2", "ALL", "BOTTOM_HALF"),
])
def test_client_hello_lengths_are_consistent(version, ciphers, order):
    """A wrong length makes the server answer a parse error, not a stack choice."""
    packet = jarm.build_client_hello(version, ciphers, order,
                                     groups=jarm.ALL_GROUPS,
                                     server_name="example.com")
    record_len = int.from_bytes(packet[3:5], "big")
    assert record_len == len(packet) - 5
    assert packet[0] == 0x16          # handshake record
    assert packet[5] == 0x01          # ClientHello
    handshake_len = int.from_bytes(packet[6:9], "big")
    assert handshake_len == len(packet) - 9


def test_tls13_probe_includes_the_mandatory_extensions():
    """Missing key_share or supported_versions => alert 109, no measurement."""
    packet = jarm.build_client_hello("1.3", "ALL", "FORWARD",
                                     groups=jarm.ALL_GROUPS,
                                     server_name="example.com")
    assert b"\x00\x2b" in packet        # supported_versions
    assert b"\x00\x33" in packet        # key_share


def test_tls12_probe_omits_tls13_only_extensions():
    packet = jarm.build_client_hello("1.2", "ALL", "FORWARD",
                                     groups=jarm.ALL_GROUPS,
                                     server_name="example.com")
    assert b"\x00\x2b" not in packet
    assert b"\x00\x0b" in packet        # ec_point_formats is legal in 1.2


def test_cipher_order_actually_changes_the_packet():
    forward = jarm.build_client_hello("1.2", "ALL", "FORWARD",
                                      groups=jarm.ALL_GROUPS)
    reverse = jarm.build_client_hello("1.2", "ALL", "REVERSE",
                                      groups=jarm.ALL_GROUPS)
    assert forward != reverse


def test_top_half_and_bottom_half_differ():
    top = jarm.build_client_hello("1.2", "ALL", "TOP_HALF",
                                  groups=jarm.ALL_GROUPS)
    bottom = jarm.build_client_hello("1.2", "ALL", "BOTTOM_HALF",
                                     groups=jarm.ALL_GROUPS)
    assert top != bottom


def test_alpn_extension_is_present_when_requested():
    with_alpn = jarm.build_client_hello("1.2", "ALL", "FORWARD",
                                        alpn=["h2"], groups=jarm.ALL_GROUPS)
    without = jarm.build_client_hello("1.2", "ALL", "FORWARD",
                                      groups=jarm.ALL_GROUPS)
    assert b"\x00\x10" in with_alpn
    assert len(with_alpn) > len(without)


# ── ServerHello parsing ─────────────────────────────────────────────────────


def _server_hello(version=b"\x03\x03", cipher=b"\xc0\x2f",
                  extra_ext=b"") -> bytes:
    """Build a minimal well-formed ServerHello for parser tests."""
    body = (
        version
        + bytes(32)                              # random
        + b"\x00"                                # empty session id
        + cipher
        + b"\x00"                                # compression
        + struct_ext(extra_ext)
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def struct_ext(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "big") + payload


def ext(kind: int, payload: bytes) -> bytes:
    return kind.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def test_parser_reads_version_and_cipher():
    raw = _server_hello(version=b"\x03\x03", cipher=b"\xc0\x2f")
    version_hex, cipher_hex, _ = jarm.parse_server_hello(raw)
    assert version_hex == "03"
    assert cipher_hex == "2f"


def test_parser_prefers_supported_versions_for_tls13():
    """TLS 1.3 replies keep 0x0303 in the legacy field; the truth is in 0x002b."""
    raw = _server_hello(
        version=b"\x03\x03", cipher=b"\x13\x01",
        extra_ext=ext(0x002b, b"\x03\x04"),
    )
    version_hex, cipher_hex, _ = jarm.parse_server_hello(raw)
    assert version_hex == "04"
    assert cipher_hex == "01"


def test_parser_extracts_alpn_bytes():
    alpn_payload = b"\x00\x03\x02h2"
    raw = _server_hello(extra_ext=ext(0x0010, alpn_payload))
    _, _, alpn_blob = jarm.parse_server_hello(raw)
    assert alpn_blob == alpn_payload


def test_parser_handles_a_non_empty_session_id():
    """A fixed offset would read the session-id length byte as the cipher."""
    session = b"\x20" + bytes(32)
    body = (b"\x03\x03" + bytes(32) + session + b"\xc0\x30" + b"\x00"
            + struct_ext(b""))
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    raw = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

    version_hex, cipher_hex, _ = jarm.parse_server_hello(raw)
    assert version_hex == "03"
    assert cipher_hex == "30"


def test_parser_marks_an_alert_as_no_answer():
    alert = b"\x15\x03\x03\x00\x02\x02\x6d"     # fatal, missing_extension
    assert jarm.parse_server_hello(alert) == ("00", "00", b"")


def test_parser_marks_garbage_as_no_answer():
    assert jarm.parse_server_hello(b"") == ("00", "00", b"")
    assert jarm.parse_server_hello(b"\x00" * 4) == ("00", "00", b"")


# ── comparison ──────────────────────────────────────────────────────────────


def test_compare_matches_identical_fingerprints():
    value = "a" * 30 + "." + "b" * 32
    assert jarm.compare(value, value) is True


def test_compare_is_case_and_space_insensitive():
    assert jarm.compare(" AAA.BBB ", "aaa.bbb") is True


def test_compare_never_matches_an_empty_fingerprint():
    assert jarm.compare("", "") is False
    assert jarm.compare("abc.def", "") is False


def test_probe_table_has_ten_entries():
    """JARM is defined as ten probes; a different count changes every hash."""
    assert len(jarm.PROBES) == 10
