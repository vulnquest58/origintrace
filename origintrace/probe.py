"""HTTP probing: fetch a page as the CDN sees it and as the origin sees it.

Two request shapes matter for origin work and they are easy to conflate:

* **Baseline** â€” ``https://target/`` resolved normally. This is what the world
  sees, usually through the CDN.
* **Vhost probe** â€” connect to a *specific IP* while still sending
  ``Host: target``. This is what asks "do you, 203.0.113.9, serve this site?"

A host that answers a vhost probe with the real page is either the origin or a
mirror. Distinguishing those is the job of the evidence layer, not this module.

Everything returns plain dictionaries so the pipeline stays testable without a
network: tests inject a fake ``fetch`` callable.
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("origintrace.probe")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

#: Bodies larger than this are truncated: titles and headers live near the top,
#: and pulling megabytes from a target is both slow and rude.
MAX_BODY = 262_144

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_FAVICON_RE = re.compile(
    r'<link[^>]+rel=["\']?(?:shortcut )?icon["\']?[^>]*href=["\']([^"\']+)',
    re.I,
)


@dataclass
class Response:
    """A minimal, immutable-ish snapshot of one HTTP exchange."""

    url: str = ""
    ip: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    @property
    def title(self) -> str:
        match = _TITLE_RE.search(self.body or "")
        return _normalise_title(match.group(1)) if match else ""

    @property
    def body_hash(self) -> str:
        """Hash of the visible-ish body, ignoring whitespace churn."""
        text = re.sub(r"\s+", " ", (self.body or "")).strip()
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def favicon_path(self) -> str:
        match = _FAVICON_RE.search(self.body or "")
        return match.group(1) if match else ""

    @property
    def server(self) -> str:
        for key, value in self.headers.items():
            if key.lower() == "server":
                return str(value)
        return ""

    def header_fingerprint(self) -> str:
        """Stable digest of the "shape" of the response headers.

        Volatile values (dates, request ids, nonces) are removed first, because
        they differ between two requests to the same server.
        """
        skip = {
            "date", "set-cookie", "cf-ray", "x-request-id", "x-amz-cf-id",
            "x-cache", "age", "x-served-by", "x-timer", "report-to", "nel",
            "etag", "last-modified", "content-length", "expires",
        }
        parts = sorted(
            f"{k.lower()}={v}"
            for k, v in self.headers.items()
            if k.lower() not in skip
        )
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @property
    def cookies(self) -> List[str]:
        for key, value in self.headers.items():
            if key.lower() == "set-cookie":
                return [value]
        return []

    def to_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "ip": self.ip,
            "status": self.status,
            "server": self.server,
            "title": self.title,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
        }


def _normalise_title(raw: str) -> str:
    text = re.sub(r"<[^>]+>", "", raw or "")
    return re.sub(r"\s+", " ", text).strip()[:200]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Fetching
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


def fetch(
    url: str,
    *,
    host_header: Optional[str] = None,
    connect_ip: Optional[str] = None,
    timeout: float = 8.0,
    verify_tls: bool = False,
) -> Response:
    """Fetch ``url``, optionally pinning the connection to ``connect_ip``.

    ``connect_ip`` is what makes a vhost probe possible: DNS is bypassed while
    the TLS SNI and the ``Host`` header still name the real target, so a server
    that hosts the site answers with the site â€” and one that does not answers
    with its default page.

    TLS verification is off by default **only** because origin servers routinely
    serve expired or self-signed certificates for the wrong name; the certificate
    content is still read and analysed by :mod:`origintrace.validation`. This is
    a deliberate trade-off, documented rather than hidden.
    """
    import httpx

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host_header:
        # httpx sets Host from the URL; a custom Host needs an explicit header.
        pass

    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if host_header:
        headers["Host"] = host_header

    response = Response(url=url, ip=connect_ip or host)
    extensions = {}
    if connect_ip:
        # Force the TCP destination while keeping SNI/Host for the vhost.
        extensions["sni_hostname"] = host_header or host

    try:
        with httpx.Client(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,
            headers=headers,
            trust_env=False,
        ) as client:
            request = client.build_request("GET", url, headers=headers,
                                          extensions=extensions or None)
            # httpx has no public "connect to this IP" switch, so the socket is
            # bound by rewriting the URL to the IP and keeping Host + SNI.
            if connect_ip:
                request.url = httpx.URL(
                    f"{parsed.scheme}://{connect_ip}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}{parsed.path or '/'}"
                )
                request.headers["Host"] = host_header or host
            started = _now_ms()
            raw = client.send(request, stream=False)
            response.status = raw.status_code
            response.headers = {k: v for k, v in raw.headers.items()}
            response.body = raw.text[:MAX_BODY]
            response.elapsed_ms = _now_ms() - started
    except Exception as exc:  # noqa: BLE001 - every failure is data here
        response.error = f"{type(exc).__name__}: {exc}"
        logger.debug("fetch failed url=%s ip=%s: %s", url, connect_ip, exc)

    return response


def _now_ms() -> int:
    import time
    return int(time.monotonic() * 1000)


def probe_vhost(ip: str, vhost: str, scheme: str = "http",
                timeout: float = 8.0) -> Response:
    """Ask ``ip`` to serve ``vhost``."""
    port = 443 if scheme == "https" else 80
    return fetch(f"{scheme}://{vhost}:{port}/", host_header=vhost,
                 connect_ip=ip, timeout=timeout)


def baseline(target: str, timeout: float = 10.0) -> Response:
    """Fetch the target the way any browser would."""
    if "://" not in target:
        target = f"https://{target}"
    return fetch(target, timeout=timeout, verify_tls=False)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TLS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


@dataclass
class Certificate:
    """What a TLS handshake revealed about one IP."""

    ok: bool = False
    error: str = ""
    subject_cn: str = ""
    sans: List[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    self_signed: bool = False
    #: True when no name in the certificate covers the requested host. This is
    #: informational — the certificate was still read successfully.
    mismatch: bool = False
    sha256: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "subject_cn": self.subject_cn,
            "sans": list(self.sans),
            "issuer": self.issuer,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "mismatch": self.mismatch,
            "sha256": self.sha256,
            "error": self.error,
        }


def certificate(ip: str, server_name: str, port: int = 443,
                timeout: float = 6.0) -> Certificate:
    """Read the certificate an IP presents for ``server_name``.

    Deliberately does not verify: an origin serving an expired or self-signed
    certificate still proves identity through its SAN entries, and refusing to
    look would discard the strongest signal available.

    The DER bytes are parsed directly rather than read from
    ``ssl.getpeercert()``. With ``verify_mode = CERT_NONE`` the stdlib returns an
    **empty dict** â€” which meant every field below stayed blank and the TLS
    evidence could never fire. That was invisible without a live test, because
    the function still reported ``ok = True``.
    """
    result = Certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    der = b""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True) or b""
    except Exception as exc:  # noqa: BLE001 - data, not failure
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    if not der:
        result.error = "no certificate presented"
        return result

    result.ok = True
    result.sha256 = hashlib.sha256(der).hexdigest()
    _fill_from_der(result, der, server_name)
    return result


def _fill_from_der(result: Certificate, der: bytes, server_name: str) -> None:
    """Populate the parsed fields from the DER certificate.

    Uses ``cryptography`` when available and falls back to the stdlib's
    ``getpeercert`` only if it returns something useful. The fallback exists so
    the module still imports on a machine without the dependency; the fields are
    then simply unknown rather than silently wrong.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:
        result.error = "cryptography not installed; certificate not parsed"
        return

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001
        result.error = f"unparseable certificate: {exc}"
        return

    def name_of(attribute):
        values = cert.subject.get_attributes_for_oid(attribute)
        return str(values[0].value) if values else ""

    result.subject_cn = name_of(NameOID.COMMON_NAME)

    issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    result.issuer = str(issuer_org[0].value) if issuer_org else (
        str(issuer_cn[0].value) if issuer_cn else ""
    )

    result.not_before = _utc_stamp(cert, "not_valid_before")
    result.not_after = _utc_stamp(cert, "not_valid_after")

    now = datetime.now(timezone.utc)
    result.expired = _utc_dt(cert, "not_valid_after") < now

    result.self_signed = cert.issuer == cert.subject

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # ``get_values_for_type`` already returns plain strings; treating them as
        # objects with a ``.value`` attribute raised AttributeError, the bare
        # except swallowed it, and every certificate reported an empty SAN list
        # — which silently disabled the strongest signal in the tool.
        result.sans = [str(name)
                       for name in san.value.get_values_for_type(x509.DNSName)]
    except Exception:  # noqa: BLE001 - absent SAN extension is normal
        result.sans = []

    # ``mismatch`` is informational, not a failure: an origin legitimately
    # presents a certificate for its own name. Keeping it out of ``error`` means
    # a caller can treat ``ok`` as "the certificate was read".
    names = [result.subject_cn] + result.sans
    if names and not any(_covers(name, server_name) for name in names if name):
        result.mismatch = True


def _utc_dt(cert, attribute: str) -> datetime:
    """Read a validity bound as an aware UTC datetime.

    ``cryptography`` deprecated the naive properties; ``*_utc`` exists from 42.0,
    and the fallback keeps the module usable on older versions.
    """
    aware = getattr(cert, f"{attribute}_utc", None)
    if aware is not None:
        return aware
    naive = getattr(cert, attribute)
    return naive.replace(tzinfo=timezone.utc)


def _utc_stamp(cert, attribute: str) -> str:
    return _utc_dt(cert, attribute).strftime("%Y-%m-%dT%H:%M:%SZ")


def _covers(pattern: str, host: str) -> bool:
    """True when a certificate name covers ``host`` (wildcards included)."""
    pattern = (pattern or "").strip().lower().rstrip(".")
    host = (host or "").strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # A wildcard covers exactly one label: *.example.com matches
        # www.example.com but not a.b.example.com.
        return host.endswith("." + suffix) and \
            host.count(".") == suffix.count(".") + 1
    return False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  DNS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


def resolve(host: str, record: str = "A") -> List[str]:
    """Resolve ``host`` to a list of values, empty on any failure."""
    try:
        import dns.resolver
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(host, record, lifetime=5)
        return [str(item).strip() for item in answers]
    except Exception:  # noqa: BLE001 - NXDOMAIN and timeouts are both "none"
        return []


def cname_chain(host: str, limit: int = 6) -> List[str]:
    """Follow CNAMEs so the CDN can be named even without an IP database."""
    chain: List[str] = []
    current = host
    for _ in range(limit):
        targets = resolve(current, "CNAME")
        if not targets:
            break
        nxt = targets[0].rstrip(".")
        chain.append(nxt)
        current = nxt
    return chain


def mx_hosts(domain: str) -> List[str]:
    """Mail exchangers are a classic origin leak: they rarely sit behind a CDN."""
    hosts: List[str] = []
    for record in resolve(domain, "MX"):
        parts = record.split()
        if parts:
            hosts.append(parts[-1].rstrip(".").lower())
    return hosts

