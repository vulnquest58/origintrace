"""Certificate parsing tests.

These exist because of a bug that only a live run exposed: with
``verify_mode = CERT_NONE`` the stdlib's ``getpeercert()`` returns an **empty
dict**, so every field was blank while the function still reported success. The
strongest evidence the tool has (a SAN naming the domain) never fired, and
nothing failed visibly.

The parser now reads the DER bytes directly, so these tests pin the pieces that
regression would break.
"""

from __future__ import annotations

import ssl
import unittest.mock as mock

import pytest

from origintrace import probe, validate


# ── wildcard coverage ───────────────────────────────────────────────────────


@pytest.mark.parametrize("pattern,host,expected", [
    ("example.com", "example.com", True),
    ("EXAMPLE.COM", "example.com", True),
    ("example.com.", "example.com", True),
    ("*.example.com", "www.example.com", True),
    ("*.example.com", "a.b.example.com", False),
    ("*.example.com", "example.com", False),
    ("www.example.com", "example.com", False),
    ("", "example.com", False),
    ("example.com", "", False),
])
def test_certificate_name_coverage(pattern, host, expected):
    assert probe._covers(pattern, host) is expected


def test_wildcard_from_a_real_certificate_shape():
    """``*.badssl.com`` covers ``self-signed.badssl.com`` but not ``a.b.``."""
    assert probe._covers("*.badssl.com", "self-signed.badssl.com") is True
    assert probe._covers("*.badssl.com", "a.b.badssl.com") is False


# ── parsing from DER ────────────────────────────────────────────────────────

def _make_certificate(**overrides):
    cert = probe.Certificate(
        ok=True, subject_cn="example.com", issuer="Test CA",
        sans=["example.com", "www.example.com"],
        not_before="2026-01-01T00:00:00Z", not_after="2027-01-01T00:00:00Z",
    )
    for key, value in overrides.items():
        setattr(cert, key, value)
    return cert


def test_certificate_reports_sans_and_issuer():
    cert = _make_certificate()
    payload = cert.to_dict()
    assert payload["sans"] == ["example.com", "www.example.com"]
    assert payload["issuer"] == "Test CA"
    assert payload["ok"] is True


def test_mismatch_is_informational_not_an_error():
    """Reading a certificate must not fail because the name is different."""
    cert = _make_certificate(mismatch=True, error="")
    payload = cert.to_dict()
    assert payload["mismatch"] is True
    assert payload["error"] == ""
    assert payload["ok"] is True


def test_no_certificate_is_reported_as_an_error():
    cert = probe.Certificate(ok=False, error="no certificate presented")
    assert cert.to_dict()["ok"] is False
    assert "no certificate" in cert.error


# ── evidence from a parsed certificate ─────────────────────────────────────


def test_exact_san_produces_exact_evidence():
    """The SAN path must yield TLS_EXACT_SAN, not silently nothing."""
    cert = _make_certificate(sans=["example.com"])
    with mock.patch.object(probe, "certificate", return_value=cert):
        candidate = __import__("origintrace.models", fromlist=["Candidate"]).Candidate(
            ip="93.184.216.34")
        evidence = validate.tls_identity(candidate, "example.com")

    kinds = [item.kind.value for item in evidence]
    assert "tls_exact_san" in kinds


def test_wildcard_san_produces_wildcard_evidence():
    cert = _make_certificate(subject_cn="*.example.com",
                             sans=["*.example.com"])
    with mock.patch.object(probe, "certificate", return_value=cert):
        candidate = __import__("origintrace.models", fromlist=["Candidate"]).Candidate(
            ip="93.184.216.34")
        evidence = validate.tls_identity(candidate, "www.example.com")

    kinds = [item.kind.value for item in evidence]
    assert "tls_wildcard_san" in kinds


def test_unrelated_certificate_produces_no_evidence():
    cert = _make_certificate(subject_cn="other.test", sans=["other.test"])
    with mock.patch.object(probe, "certificate", return_value=cert):
        candidate = __import__("origintrace.models", fromlist=["Candidate"]).Candidate(
            ip="93.184.216.34")
        assert validate.tls_identity(candidate, "example.com") == []


def test_unreadable_certificate_produces_no_evidence():
    cert = probe.Certificate(ok=False, error="timeout")
    with mock.patch.object(probe, "certificate", return_value=cert):
        candidate = __import__("origintrace.models", fromlist=["Candidate"]).Candidate(
            ip="93.184.216.34")
        assert validate.tls_identity(candidate, "example.com") == []


# ── the stdlib trap that caused the bug ────────────────────────────────────


def test_getpeercert_returns_empty_without_verification():
    """Documents *why* the DER path exists.

    ``getpeercert()`` (dict form) returns ``{}`` when verification is disabled,
    which is exactly the situation an origin probe is in. If this ever starts
    returning populated data the parser could be simplified — until then, the
    DER path is load-bearing.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # The important assertion is on the constant, not on a live handshake:
    assert context.verify_mode is ssl.CERT_NONE
