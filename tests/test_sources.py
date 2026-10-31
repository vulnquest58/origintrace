"""Tests for the advanced sources and the TLS fingerprint module.

All offline: every third-party call is faked, so these prove the parsing and the
decision logic rather than network reachability.
"""

from __future__ import annotations

import pytest

from origintrace import discover, sources, tlsfp
from origintrace.models import EvidenceKind, Candidate


# â”€â”€ SPF / DMARC parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_spf_extracts_literal_and_named_entries(monkeypatch):
    record = ("v=spf1 ip4:93.184.216.37 a:mail.example.com "
              "mx:mx.example.com include:_spf.example.com ~all")
    monkeypatch.setattr(sources, "_txt", lambda name: [record])

    hits = dict(sources.from_spf("example.com"))
    assert "93.184.216.37" in hits
    assert "mail.example.com" in hits
    assert "mx.example.com" in hits


def test_spf_ignores_records_that_are_not_spf(monkeypatch):
    monkeypatch.setattr(sources, "_txt", lambda name: ["some-verification=abc"])
    assert list(sources.from_spf("example.com")) == []


def test_spf_drops_hosts_outside_the_domain(monkeypatch):
    monkeypatch.setattr(sources, "_txt",
                        lambda name: ["v=spf1 a:mail.other.net ~all"])
    assert list(sources.from_spf("example.com")) == []


def test_dmarc_extracts_reporting_host(monkeypatch):
    monkeypatch.setattr(
        sources, "_txt",
        lambda name: ["v=DMARC1; p=none; rua=mailto:dmarc@reports.example.com"],
    )
    hits = dict(sources.from_dmarc("example.com"))
    assert "reports.example.com" in hits


# â”€â”€ CSP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_csp_lists_trusted_origins():
    headers = {
        "Content-Security-Policy":
            "default-src 'self'; connect-src https://api.example.com "
            "https://internal.example.com; img-src https://cdn.other.net"
    }
    found = set(host for host, _ in sources.from_csp(headers, "example.com"))
    assert "api.example.com" in found
    assert "internal.example.com" in found
    # A third-party CDN is not the target's own infrastructure.
    assert "cdn.other.net" not in found


def test_csp_matches_report_only_variant():
    headers = {"content-security-policy-report-only": "default-src https://a.example.com"}
    assert list(sources.from_csp(headers, "example.com"))


# â”€â”€ generic header scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_generic_header_scan_finds_embedded_hosts():
    headers = {"X-Debug-Origin": "backend.internal.example.com:8080"}
    found = dict(sources.from_headers_generic(headers, "example.com"))
    assert "backend.internal.example.com" in found


# â”€â”€ robots / sitemap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_robots_extracts_named_hosts(monkeypatch):
    body = "User-agent: *\nSitemap: https://staging.example.com/sitemap.xml\n"
    monkeypatch.setattr(sources, "_http", lambda *a, **k: body)
    found = dict(sources.from_robots("example.com"))
    assert "staging.example.com" in found


def test_sitemap_extracts_named_hosts(monkeypatch):
    body = "<urlset><url><loc>https://shop.example.com/x</loc></url></urlset>"
    monkeypatch.setattr(sources, "_http", lambda *a, **k: body)
    found = dict(sources.from_sitemap("example.com"))
    assert "shop.example.com" in found


def test_noise_domains_are_filtered():
    assert sources._clean("cdn.jsdelivr.net", "example.com") == ""
    assert sources._clean("x.w3.org", "example.com") == ""
    assert sources._clean("web.example.com", "example.com") == "web.example.com"


# â”€â”€ discovery driver â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_discovery_resolves_hostnames_returned_by_sources(monkeypatch):
    """A source may return a name; the driver turns it into an address."""
    fake = discover.Source("fake", lambda domain: [("host.example.com", "detail")])
    monkeypatch.setattr(discover.probe, "resolve",
                        lambda host, record="A": ["93.184.216.36"])
    found = discover.discover("example.com", sources=[fake])
    assert "93.184.216.36" in found


def test_discovery_reports_progress_per_source(monkeypatch):
    seen = []
    fake = discover.Source("fake", lambda domain: [("93.184.216.35", "d")])
    discover.discover("example.com", sources=[fake],
                      progress=lambda name, count, err: seen.append((name, count, err)))
    assert seen and seen[0][0] == "fake"
    assert seen[0][2] == ""


def test_one_failing_source_does_not_stop_the_others(monkeypatch):
    def boom(domain):
        raise RuntimeError("api down")

    good = discover.Source("good", lambda domain: [("93.184.216.34", "d")])
    found = discover.discover("example.com",
                              sources=[discover.Source("bad", boom), good])
    assert "93.184.216.34" in found


# â”€â”€ non-routable safety guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@pytest.mark.parametrize("address", [
    "10.32.10.95",      # the leak seen in a real run against iana.org
    "192.168.1.5",
    "172.16.0.9",
    "127.0.0.1",
    "169.254.1.1",
    "224.0.0.1",
    "0.0.0.0",
    "::1",
])
def test_non_routable_addresses_are_not_probeable(address):
    """Probing these would send traffic to the operator's own network."""
    assert discover.is_probeable(address) is False


@pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700::1111"])
def test_public_addresses_are_probeable(address):
    assert discover.is_probeable(address) is True


def test_discovery_drops_private_addresses_entirely(monkeypatch):
    """A leaked internal hostname must never become a candidate."""
    fake = discover.Source(
        "fake", lambda domain: [("10.32.10.95", "mx leak"),
                                ("93.184.216.34", "public")])
    found = discover.discover("example.com", sources=[fake])
    assert "10.32.10.95" not in found
    assert "93.184.216.34" in found


def test_private_address_reached_via_hostname_is_also_dropped(monkeypatch):
    fake = discover.Source("fake", lambda domain: [("internal.example.com", "x")])
    monkeypatch.setattr(discover.probe, "resolve",
                        lambda host, record="A": ["10.47.10.22"])
    assert discover.discover("example.com", sources=[fake]) == {}


def test_extended_sources_include_the_header_driven_ones():
    wired = discover.extended_sources({"Content-Security-Policy": "default-src 'self'"})
    names = {source.name for source in wired}
    assert "csp" in names
    assert "spf" in names


# â”€â”€ TLS fingerprint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _fp(**kwargs) -> tlsfp.TlsFingerprint:
    base = dict(ok=True, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                bits=256, alpn="http/1.1", cert_key_type="rsa")
    base.update(kwargs)
    return tlsfp.TlsFingerprint(**base)


def test_identical_stacks_produce_equal_digests():
    assert _fp().digest == _fp().digest


def test_different_cipher_changes_the_digest():
    assert _fp().digest != _fp(cipher="TLS_AES_128_GCM_SHA256").digest


def test_different_version_changes_the_digest():
    assert _fp().digest != _fp(version="TLSv1.2").digest


def test_legacy_protocol_support_changes_the_digest():
    assert _fp().digest != _fp(legacy_protocols=True).digest


def test_compare_requires_both_handshakes_to_succeed():
    baseline = _fp()
    failed = tlsfp.TlsFingerprint(ok=False, error="refused")
    assert tlsfp.compare(baseline, failed) is False


def test_compare_matches_identical_stacks():
    assert tlsfp.compare(_fp(), _fp()) is True


def test_compare_rejects_different_stacks():
    assert tlsfp.compare(_fp(), _fp(cipher="TLS_CHACHA20_POLY1305_SHA256")) is False


def test_failed_fingerprint_reports_no_digest():
    assert tlsfp.TlsFingerprint(ok=False, error="x").digest != ""


# â”€â”€ evidence kind wiring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_tls_fingerprint_match_has_a_declared_weight():
    """The weight table must cover every kind a module can emit."""
    from origintrace import evidence
    assert EvidenceKind.TLS_JARM_MATCH in evidence.WEIGHTS
    assert EvidenceKind.SPF_OR_MX_LEAK in evidence.WEIGHTS

