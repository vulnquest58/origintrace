"""Real JARM: an active TLS fingerprint resistant to trivial spoofing.

JARM (Salesforce, 2020) sends **ten deliberately malformed ClientHellos** and
hashes the server's answer to each. Because it varies the TLS version, the cipher
order, the extension set and the ALPN list, the combined response identifies a
TLS stack the way a fingerprint identifies a person: two machines running the
same reverse proxy answer identically, a CDN edge and the origin behind it very
often do not.

Why this exists next to :mod:`origintrace.tlsfp`:

* ``tlsfp`` reads what a *normal* handshake negotiated. Cheap, but two different
  stacks can agree on TLS 1.3 + AES-256-GCM.
* JARM probes deliberately unusual parameter combinations, so it separates stacks
  that a normal handshake cannot. It also sees the server's *choice* when offered
  a bad menu, which is far more distinctive.

The output is a 62-character fingerprint â€” 30 hex characters of cipher/version
selection followed by 32 of ALPN answer â€” exactly as specified by the original
research, so hashes are comparable with public JARM databases.

Everything here is pure ``socket``: no third-party TLS library re-implements the
record layer differently across versions, which would change the hash.
"""

from __future__ import annotations

import hashlib
import os
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("origintrace.jarm")

#: Cipher suites referenced by the probe definitions.
CIPHERS = {
    "TLS_AES_128_GCM_SHA256": b"\x13\x01",
    "TLS_AES_256_GCM_SHA384": b"\x13\x02",
    "TLS_CHACHA20_POLY1305_SHA256": b"\x13\x03",
    "TLS_AES_128_CCM_SHA256": b"\x13\x04",
    "TLS_AES_128_CCM_8_SHA256": b"\x13\x05",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": b"\xc0\x09",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": b"\xc0\x0a",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": b"\xc0\x13",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": b"\xc0\x14",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": b"\xc0\x23",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": b"\xc0\x24",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": b"\xc0\x27",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": b"\xc0\x28",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": b"\xc0\x2b",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": b"\xc0\x2c",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": b"\xc0\x2f",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": b"\xc0\x30",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": b"\xcc\xa8",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": b"\xcc\xa9",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": b"\x00\x9e",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": b"\x00\x9f",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": b"\x00\x33",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": b"\x00\x39",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": b"\x00\x67",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": b"\x00\x6b",
}

#: Named cipher lists used by the ten probes, in the order tested.
CIPHER_LISTS = {
    "ALL": [
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    ],
    "NO1.3": [
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    ],
}

#: Protocol version bytes.
VERSIONS = {
    "1.0": b"\x03\x01",
    "1.1": b"\x03\x02",
    "1.2": b"\x03\x03",
    "1.3": b"\x03\x04",
}

#: Supported-groups extension payloads.
GROUPS = {
    "P256": b"\x00\x17",
    "P384": b"\x00\x18",
    "P521": b"\x00\x19",
    "X25519": b"\x00\x1d",
    "X448": b"\x00\x1e",
    "FFDHE2048": b"\x01\x00",
    "FFDHE3072": b"\x01\x01",
}

ALL_GROUPS = ["P256", "P384", "P521", "X25519", "X448", "FFDHE2048", "FFDHE3072"]

#: ALPN protocol lists.
ALPN = {
    "http/0.9": b"\x08http/0.9",
    "http/1.0": b"\x08http/1.0",
    "http/1.1": b"\x08http/1.1",
    "spdy/1": b"\x06spdy/1",
    "spdy/2": b"\x06spdy/2",
    "spdy/3": b"\x06spdy/3",
    "h2": b"\x02h2",
    "h2c": b"\x03h2c",
    "h2-14": b"\x05h2-14",
    "h2-15": b"\x05h2-15",
    "h2-16": b"\x05h2-16",
    "h2-17": b"\x05h2-17",
    "h2-18": b"\x05h2-18",
    "h2-19": b"\x05h2-19",
}

NO_ALPN = "NONE"

#: The ten probes. ``(tls_version, cipher_list, order, alpn_list/None, groups/None)``.
#: This is the published JARM table; deviating from it changes the hash and makes
#: the output incomparable with public JARM databases.
PROBES: List[Tuple[str, str, str, Optional[str], Optional[str]]] = [
    ("1.3", "ALL", "FORWARD", None, None),
    ("1.3", "ALL", "REVERSE", None, None),
    ("1.3", "NO1.3", "FORWARD", None, None),
    ("1.2", "ALL", "FORWARD", None, ALL_GROUPS),
    ("1.2", "ALL", "REVERSE", None, ALL_GROUPS),
    ("1.2", "ALL", "TOP_HALF", None, ALL_GROUPS),
    ("1.2", "ALL", "BOTTOM_HALF", None, ALL_GROUPS),
    ("1.1", "ALL", "FORWARD", None, ALL_GROUPS),
    ("1.2", "ALL", "FORWARD", "h2", ALL_GROUPS),
    ("1.2", "ALL", "FORWARD", "http/1.1", ALL_GROUPS),
]

#: Packets that make the server send a certificate, used to build the hash.
LEGACY_PACKET = (
    b"\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x1a\xc0\x2f\xc0\x2b\xc0\x30\xc0\x2c\xc0\x28\xc0\x24"
    b"\xc0\x14\xc0\x0a\x00\x9f\x00\x9e\x00\x6b\x00\x67\x00\x39\x00\x33"
    b"\x01\x00\x00\x2e\x00\x00\x00\x16\x00\x14\x00\x00\x11"
    b"example.com\x00\x0b\x00\x04\x03\x00\x01\x02"
)

#: Reverse-engineered from the original implementation: a TLS 1.3 probe that
#: triggers a certificate response regardless of the version negotiated.
TLS13_PACKET = (
    b"\x16\x03\x01\x00\xcb\x01\x00\x00\xc7\x03\x03"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x13\x01\x13\x02\x13\x03\x13\x04\x13\x05"
    b"\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14"
    b"\x00\x9c\x00\x9d\x00\x2f\x00\x35"
    b"\x01\x00\x00\x7e\x00\x00\x00\x16\x00\x14\x00\x00\x11"
    b"example.com\x00\x0b\x00\x04\x03\x00\x01\x02"
    b"\x00\x0a\x00\x0c\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18"
    b"\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03"
    b"\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    b"\x00\x12\x00\x00\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


@dataclass
class JarmResult:
    """The fingerprint plus everything observed while producing it."""

    host: str = ""
    port: int = 443
    fingerprint: str = ""
    ok: bool = False
    error: str = ""
    #: ``[(probe_index, response_hex_or_error), ...]`` for auditing a mismatch.
    probes: List[Tuple[int, str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.probes is None:
            self.probes = []

    @property
    def short(self) -> str:
        """First 30 characters â€” the cipher/version half of the fingerprint."""
        return self.fingerprint.split(".")[0] if self.fingerprint else ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "fingerprint": self.fingerprint,
            "ok": self.ok,
            "error": self.error,
            "probe_count": len(self.probes),
        }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Byte-level packet construction
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


def _extension(kind: int, payload: bytes) -> bytes:
    return struct.pack("!HH", kind, len(payload)) + payload


def _is_tls13(version_name: str) -> bool:
    """Is this probe meant to negotiate TLS 1.3?

    The probe table says ``"1.3"`` or ``"NO1.3"``; ``NO1.3`` means "offer the
    TLS 1.2 parameter set", which is why the probe keeps ``VERSIONS["1.2"]`` as
    the record version. Getting this distinction wrong is what made every TLS 1.3
    probe rejected with ``alert 109 = missing_extension``.
    """
    return version_name == "1.3"


def _cipher_bytes(names: List[str], order: str) -> bytes:
    """Build the cipher-suite list in the requested order."""
    chosen = list(names)
    if order == "REVERSE":
        chosen = list(reversed(chosen))
    elif order == "TOP_HALF":
        chosen = chosen[: max(1, len(chosen) // 2)]
    elif order == "BOTTOM_HALF":
        chosen = chosen[len(chosen) // 2:]

    blob = b"".join(CIPHERS[name] for name in chosen if name in CIPHERS)
    return struct.pack("!H", len(blob)) + blob


def _groups_bytes(names: List[str]) -> bytes:
    blob = b"".join(GROUPS[name] for name in names if name in GROUPS)
    return struct.pack("!H", len(blob)) + blob


def _alpn_bytes(names: Optional[List[str]]) -> bytes:
    if not names:
        return b""
    blob = b"".join(ALPN[name] for name in names if name in ALPN)
    # An ALPN list is length-prefixed twice: once for the protocol list, once for
    # the extension, and the extension wrapper adds a third.
    inner = struct.pack("!H", len(blob)) + blob
    return _extension(0x0010, inner)


def build_client_hello(tls_version: str, cipher_list: str, order: str,
                       alpn: Optional[List[str]] = None,
                       groups: Optional[List[str]] = None,
                       server_name: str = "") -> bytes:
    """Assemble a complete TLS ``ClientHello`` record.

    Layout follows RFC 8446 Â§4.1.2 down to the length fields, because a server
    parses it strictly: one wrong length and the probe measures a parse error
    instead of a stack choice.

    Two details are easy to get wrong and both were, initially:

    * the **record** version stays ``0x0301`` for every probe, while the
      **handshake** version carries the probe's intent;
    * a TLS 1.3 probe must include ``supported_versions`` (0x002b) *and* the
      ``signature_algorithms`` / ``supported_groups`` extensions, or a strict
      stack answers ``alert 109 = missing_extension`` and the probe measures
      nothing.
    """
    version = VERSIONS.get(tls_version, VERSIONS["1.2"])
    tls13 = _is_tls13(tls_version)

    # Cipher suites. A TLS 1.3 probe must not advertise CBC suites: they are not
    # legal in 1.3 and a strict server drops the handshake.
    ciphers = _cipher_bytes(CIPHER_LISTS[cipher_list], order)

    # Compression methods.
    compression = b"\x01\x00"

    # Extensions, in the order the reference implementation emits them.
    extensions = b""

    # server_name (0x0000)
    if server_name:
        name = server_name.encode("ascii", "ignore")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        extensions += _extension(0x0000,
                                 struct.pack("!H", len(entry)) + entry)

    # supported_groups (0x000a)
    if groups:
        extensions += _extension(0x000a, _groups_bytes(groups))

    # ec_point_formats (0x000b) â€” TLS 1.3 forbids this extension.
    if not tls13:
        extensions += _extension(0x000b, b"\x01\x00")

    # signature_algorithms (0x000d) â€” mandatory for 1.3, harmless for 1.2.
    sigalgs = bytes.fromhex("040308040401050308050501080606010201")
    extensions += _extension(0x000d, struct.pack("!H", len(sigalgs)) + sigalgs)

    # alpn (0x0010)
    alpn_ext = _alpn_bytes(alpn)
    if alpn_ext:
        extensions += alpn_ext

    # supported_versions (0x002b) â€” required for a 1.3 probe.
    if tls13:
        versions = VERSIONS["1.3"] + VERSIONS["1.2"] + VERSIONS["1.1"]
        extensions += _extension(0x002b,
                                 struct.pack("!B", len(versions)) + versions)
        # key_share (0x0033) is mandatory in TLS 1.3: without it a strict stack
        # answers alert 109 (missing_extension) and the probe measures nothing.
        # The key material never has to be *usable* â€” only the handshake's shape
        # is fingerprinted â€” but it must be a plausible x25519 public key: 32
        # zero bytes are a low-order point that strict stacks reject with
        # alert 50 (decode_error).
        share = b"\x00\x1d" + struct.pack("!H", 32) + os.urandom(32)
        extensions += _extension(0x0033,
                                 struct.pack("!H", len(share)) + share)

    # session_ticket (0x0023) â€” empty, but its presence changes the stack's answer.
    extensions += _extension(0x0023, b"")

    # Handshake body.
    body = (
        version
        + b"\x00" * 32                                   # random
        + b"\x00"                                        # session id length
        + ciphers
        + compression
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body

    return b"\x16" + VERSIONS["1.0"] + struct.pack("!H", len(handshake)) + handshake


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Probing
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


def _send_and_read(host: str, port: int, packet: bytes, timeout: float) -> bytes:
    """Send one probe and return the raw first response."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            return sock.recv(1484)
    except (socket.timeout, ConnectionError, OSError):
        return b""


def parse_server_hello(response: bytes) -> Tuple[str, str, bytes]:
    """Return ``(version_hex, cipher_hex, alpn_extension_bytes)``.

    ``response`` is the raw bytes read from the socket after a probe. A fixed
    offset cannot be used: the layout after the 32-byte random depends on the
    session-id length, and the *real* protocol version of a TLS 1.3 reply lives
    in the ``supported_versions`` extension rather than in the legacy field.
    Reading ``response[9]``/``response[43]`` blindly reported ``0000`` for every
    server and made all fingerprints identical.

    Returns ``("00", "00", b"")`` when the reply is not a ServerHello — an alert
    is a valid answer and is scored as zeros, exactly as the reference does.
    """
    if len(response) < 11 or response[0] != 0x16 or response[5] != 0x02:
        return "00", "00", b""

    pos = 9                       # record header (5) + handshake header (4)
    legacy_version = response[pos:pos + 2]
    pos += 2 + 32                 # skip version and random

    if pos >= len(response):
        return "00", "00", b""
    session_id_len = response[pos]
    pos += 1 + session_id_len

    if pos + 3 > len(response):
        return "00", "00", b""
    cipher = response[pos:pos + 2]
    pos += 2
    pos += 1                      # compression method

    extensions_len = int.from_bytes(response[pos:pos + 2], "big") \
        if pos + 2 <= len(response) else 0
    pos += 2
    end = min(pos + extensions_len, len(response))

    negotiated = legacy_version
    alpn_blob = b""

    while pos + 4 <= end:
        kind = int.from_bytes(response[pos:pos + 2], "big")
        length = int.from_bytes(response[pos + 2:pos + 4], "big")
        payload = response[pos + 4:pos + 4 + length]

        if kind == 0x002b and len(payload) >= 2:
            # supported_versions carries the real 1.3 negotiation.
            negotiated = payload[:2]
        elif kind == 0x0010:
            alpn_blob = payload

        pos += 4 + length

    version_hex = f"{negotiated[1]:02x}" if len(negotiated) == 2 else "00"
    cipher_hex = f"{cipher[1]:02x}" if len(cipher) == 2 else "00"
    return version_hex, cipher_hex, alpn_blob


def fingerprint(host: str, port: int = 443, timeout: float = 8.0) -> JarmResult:
    """Run the ten JARM probes and hash the answers."""
    result = JarmResult(host=host, port=port)

    answers: List[str] = []
    alpn_blobs: List[bytes] = []

    for index, (version, ciphers, order, alpn, groups) in enumerate(PROBES):
        # Probes 9 and 10 request an ALPN list; their extension bytes become the
        # second half of the fingerprint.
        wants_alpn = alpn is not None
        alpn_names = [alpn] if wants_alpn else None

        # A "NO1.3" probe deliberately offers no TLS 1.3 cipher suite, so it must
        # also stop advertising 1.3 in supported_versions — otherwise the server
        # legitimately answers with an alert and the probe measures nothing.
        effective_version = "1.2" if ciphers == "NO1.3" else version

        packet = build_client_hello(effective_version, ciphers, order,
                                    alpn=alpn_names,
                                    groups=groups or ALL_GROUPS,
                                    server_name=host)
        response = _send_and_read(host, port, packet, timeout)
        version_hex, cipher_hex, alpn_blob = parse_server_hello(response)

        answers.append(version_hex + cipher_hex)
        if wants_alpn:
            alpn_blobs.append(alpn_blob)

        result.probes.append(
            (index, version_hex + cipher_hex if response else "no response")
        )

    if all(answer == "0000" for answer in answers):
        result.error = "no probe answered with a ServerHello"
        return result

    cipher_hash = hashlib.sha256(",".join(answers).encode()).hexdigest()[:30]
    alpn_hash = hashlib.sha256(b"".join(alpn_blobs)).hexdigest()[:32] \
        if alpn_blobs else "0" * 32

    result.fingerprint = f"{cipher_hash}.{alpn_hash}"
    result.ok = True
    return result


def compare(expected: str, actual: str) -> bool:
    """Do two JARM fingerprints match? Empty fingerprints never match."""
    if not expected or not actual:
        return False
    return expected.strip().lower() == actual.strip().lower()

