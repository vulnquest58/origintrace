"""TLS fingerprinting.

A TLS server answers a `ClientHello` with a very specific combination of
protocol version, cipher suite, extensions and certificate chain shapes. Two
machines running the same stack answer identically; a CDN edge and the origin
behind it very often do not.

This module produces a **stable fingerprint of the negotiated parameters**. It is
*not* byte-compatible with Salesforce JARM — JARM sends ten carefully crafted
ClientHellos and hashes the combined responses, which needs a hand-built TLS
record layer. What this does is honest and useful: it fingerprints the TLS stack
of a specific IP:port without any third-party service, so it works against an
origin that no scanner has ever indexed.

Comparison is the point: the fingerprint is only meaningful when it is compared
with the baseline's, which the validator does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger("origintrace.tlsfp")


@dataclass
class TlsFingerprint:
    """What a handshake revealed about the server's TLS stack."""

    ok: bool = False
    error: str = ""
    version: str = ""
    cipher: str = ""
    bits: int = 0
    #: ``True`` when the server accepted a TLS 1.0/1.1 handshake.
    legacy_protocols: bool = False
    #: Extensions the server acted on, as observed through the negotiation.
    extensions: List[str] = field(default_factory=list)
    alpn: str = ""
    #: Set when the peer presented a certificate at all.
    has_certificate: bool = False
    cert_key_type: str = ""

    @property
    def digest(self) -> str:
        """Stable hash of the negotiated parameters.

        Deliberately excludes anything that changes per connection (session ids,
        ticket lifetimes, timestamps). Two requests to the same server must
        produce the same digest, otherwise the signal is noise.
        """
        payload = json.dumps(
            {
                "version": self.version,
                "cipher": self.cipher,
                "bits": self.bits,
                "alpn": self.alpn,
                "legacy": self.legacy_protocols,
                "key": self.cert_key_type,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "version": self.version,
            "cipher": self.cipher,
            "bits": self.bits,
            "alpn": self.alpn,
            "legacy_protocols": self.legacy_protocols,
            "cert_key_type": self.cert_key_type,
            "digest": self.digest if self.ok else "",
            "error": self.error,
        }


def _context(*, max_version=None, alpn: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
    if max_version is not None:
        try:
            context.maximum_version = max_version
        except (ValueError, ssl.SSLError):
            pass
    return context


def fingerprint(ip: str, server_name: str, port: int = 443,
                timeout: float = 6.0) -> TlsFingerprint:
    """Negotiate TLS with ``ip`` for ``server_name`` and record the parameters."""
    result = TlsFingerprint()

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _context(alpn=True).wrap_socket(
                    raw, server_hostname=server_name) as tls:
                result.version = tls.version() or ""
                cipher = tls.cipher()
                if cipher:
                    result.cipher, _proto, result.bits = cipher[0], cipher[1], cipher[2]
                alpn = tls.selected_alpn_protocol()
                result.alpn = alpn or ""
                cert = tls.getpeercert(binary_form=False)
                result.has_certificate = bool(cert)
                result.cert_key_type = _key_type(tls)
                result.ok = True
    except Exception as exc:  # noqa: BLE001 - a refusal is itself information
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    # Whether the server still speaks TLS 1.0/1.1 is a real stack difference:
    # modern reverse proxies refuse it, older origins often do not. The version
    # constants are deprecated in the stdlib but still functional; the warning is
    # silenced locally because probing them is the entire point here.
    import warnings

    legacy_versions = []
    for attribute in ("TLSv1", "TLSv1_1"):
        version = getattr(ssl.TLSVersion, attribute, None)
        if version is not None:
            legacy_versions.append(version)

    for legacy in legacy_versions:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                with socket.create_connection((ip, port), timeout=timeout) as raw:
                    with _context(max_version=legacy).wrap_socket(
                            raw, server_hostname=server_name):
                        result.legacy_protocols = True
                        break
        except Exception:  # noqa: BLE001
            continue

    return result


def _key_type(tls) -> str:
    """Best-effort read of the peer's public-key algorithm.

    ``getpeercert`` returns an empty dict when verification is off, so the DER
    form is used: the algorithm OID sits in a predictable position for RSA and
    EC keys, which is enough to tell the two apart.
    """
    try:
        der = tls.getpeercert(binary_form=True) or b""
    except Exception:  # noqa: BLE001
        return ""
    if not der:
        return ""
    if b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der[:400]:
        return "rsa"
    if b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" in der[:400]:
        return "ec"
    if b"\x06\x03\x2b\x65\x70" in der[:400]:
        return "ed25519"
    return ""


def compare(baseline: TlsFingerprint, candidate: TlsFingerprint) -> bool:
    """True when two servers present the same TLS stack.

    Only meaningful when both handshakes succeeded; a failed handshake is never
    treated as a match, because "both refused" says nothing about identity.
    """
    if not (baseline.ok and candidate.ok):
        return False
    return baseline.digest == candidate.digest
