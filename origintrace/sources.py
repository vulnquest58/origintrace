"""Extended passive discovery.

Every source here answers a question a third party already knows the answer to.
None of them touch the target, which keeps the tool quiet and inside the rules of
programs that forbid active scanning of ancillary infrastructure.

Sources are grouped by the leak they exploit:

* **DNS records** — SPF, DMARC, TXT and MX often name hosts that never went
  behind the CDN, because mail and verification flows predate it.
* **Published files** — ``robots.txt`` and ``sitemap.xml`` list internal or
  staging hostnames that the marketing site does not link to.
* **Response headers** — a ``Content-Security-Policy`` frequently enumerates the
  real backend origins, which is why it is such a good leak.
* **Archives** — the Wayback Machine holds hostnames from before the CDN was
  introduced.
* **Reverse lookups** — asking "what else is on this IP" finds siblings.

Each function returns ``(value, detail)`` pairs. ``value`` may be a hostname or an
IP; the discovery driver resolves hostnames, so a source can return whichever it
naturally has.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Iterable, Iterator, List, Set, Tuple

logger = logging.getLogger("origintrace.sources")

Hit = Tuple[str, str]

#: Hostnames that are never an origin even if they appear in a leak.
NOISE = re.compile(
    r"(^|\.)(w3\.org|schema\.org|googleapis\.com|gstatic\.com|"
    r"cloudflare\.com|cloudflareinsights\.com|jsdelivr\.net|unpkg\.com|"
    r"bootstrapcdn\.com|fontawesome\.com|sentry\.io|segment\.io|"
    r"doubleclick\.net|googletagmanager\.com|hotjar\.com|intercom\.io)$",
    re.I,
)


def _http(url: str, timeout: float = 10.0, as_json: bool = False):
    """GET a third-party endpoint; ``None`` on any failure."""
    try:
        import httpx
        with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=True,
                          headers={"User-Agent": "origintrace/1.0"}) as client:
            response = client.get(url)
            if response.status_code != 200:
                return None
            return response.json() if as_json else response.text
    except Exception as exc:  # noqa: BLE001
        logger.debug("source %s failed: %s", url, exc)
        return None


def _clean(host: str, domain: str) -> str:
    """Normalise a hostname and drop anything outside the target's own suffix."""
    host = str(host).strip().lower().rstrip(".")
    host = host.lstrip("*.")
    if not host or " " in host or host == domain:
        return ""
    if not host.endswith(domain):
        return ""
    if NOISE.search(host):
        return ""
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return ""
    return host


# ══════════════════════════════════════════════════════════════════════════════
#  DNS record leaks
# ══════════════════════════════════════════════════════════════════════════════


def from_spf(domain: str) -> Iterator[Hit]:
    """Parse SPF for ``a:``/``mx:``/``ip4:`` entries.

    SPF record bodies are a classic origin leak: they list the addresses that send
    mail for the domain, and mail infrastructure is rarely rehomed behind a CDN
    when a site is.
    """
    for record in _txt(domain):
        if "v=spf1" not in record.lower():
            continue
        for token in record.split():
            lowered = token.lower()
            if lowered.startswith(("ip4:", "ip6:")):
                yield token.split(":", 1)[1], "spf: literal address"
            elif lowered.startswith(("a:", "mx:", "a", "mx")) or ":" in lowered:
                host = token.split(":", 1)[-1].lstrip("=/").rstrip("/")
                host = host.split("~")[0].split("-")[0]
                cleaned = _clean(host, domain)
                if cleaned:
                    yield cleaned, f"spf: {token}"
            elif lowered.startswith(("include:", "redirect=")):
                host = lowered.split(":", 1)[-1].split("=", 1)[-1]
                cleaned = _clean(host, domain)
                if cleaned:
                    yield cleaned, f"spf: {token}"


def from_dmarc(domain: str) -> Iterator[Hit]:
    """DMARC ``rua``/``ruf`` mailboxes often point at internal reporting hosts."""
    for record in _txt(f"_dmarc.{domain}"):
        for match in re.finditer(r"(?:rua|ruf)=mailto:([^;,\s]+)", record, re.I):
            host = match.group(1).split("@")[-1]
            cleaned = _clean(host, domain)
            if cleaned:
                yield cleaned, "dmarc: reporting host"


def from_txt_verification(domain: str) -> Iterator[Hit]:
    """Site-verification TXT records name hosts that may be self-hosted."""
    for record in _txt(domain):
        for match in re.finditer(
                r"(?:verify|verification|domain)[^=]*=\s*([a-z0-9.-]+\." +
                re.escape(domain) + r")", record, re.I):
            cleaned = _clean(match.group(1), domain)
            if cleaned:
                yield cleaned, "txt: verification host"


def _txt(name: str) -> List[str]:
    try:
        from origintrace import probe
        return probe.resolve(name, "TXT")
    except Exception:  # noqa: BLE001
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  Published files
# ══════════════════════════════════════════════════════════════════════════════


def from_robots(domain: str) -> Iterator[Hit]:
    """``robots.txt`` frequently lists admin and staging hosts by name."""
    body = _http(f"https://{domain}/robots.txt")
    if not body:
        return
    for line in body.splitlines():
        if ":" not in line:
            continue
        value = line.split(":", 1)[1].strip()
        for candidate in re.findall(r"[a-z0-9][a-z0-9.-]*\." + re.escape(domain),
                                    value, re.I):
            cleaned = _clean(candidate, domain)
            if cleaned:
                yield cleaned, "robots: hostname listed"


def from_sitemap(domain: str) -> Iterator[Hit]:
    """``sitemap.xml`` can reference hosts the marketing site never links."""
    body = _http(f"https://{domain}/sitemap.xml")
    if not body:
        return
    pattern = r"https?://([a-z0-9][a-z0-9.-]*\." + re.escape(domain) + r")"
    for candidate in set(re.findall(pattern, body, re.I)):
        cleaned = _clean(candidate, domain)
        if cleaned:
            yield cleaned, "sitemap: hostname listed"


def from_wayback(domain: str) -> Iterator[Hit]:
    """Archive hostnames from before the CDN was introduced."""
    data = _http("https://web.archive.org/cdx/search/cdx?url=*." + domain
                 + "&output=json&fl=original&collapse=urlkey&limit=400",
                 as_json=True)
    if not isinstance(data, list):
        return
    seen: Set[str] = set()
    for row in data[1:]:
        if not row:
            continue
        match = re.match(r"https?://([^/:]+)", str(row[0]), re.I)
        if not match:
            continue
        cleaned = _clean(match.group(1), domain)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            yield cleaned, "wayback: archived hostname"


# ══════════════════════════════════════════════════════════════════════════════
#  Response header leaks
# ══════════════════════════════════════════════════════════════════════════════


def from_csp(headers: dict, domain: str) -> Iterator[Hit]:
    """A ``Content-Security-Policy`` enumerates every origin the page trusts.

    This is the single most under-used passive leak: the header has to list the
    real backends for the browser to allow them, so it names infrastructure that
    may never appear anywhere else.
    """
    for key, value in (headers or {}).items():
        if key.lower() not in ("content-security-policy",
                               "content-security-policy-report-only"):
            continue
        for directive in str(value).split(";"):
            for token in directive.split():
                match = re.match(r"https?://([^/:]+)", token, re.I)
                host = match.group(1) if match else token
                cleaned = _clean(host, domain)
                if cleaned:
                    yield cleaned, "csp: trusted origin"


def from_headers_generic(headers: dict, domain: str) -> Iterator[Hit]:
    """Any header value that embeds a hostname under the target's suffix."""
    pattern = r"([a-z0-9][a-z0-9.-]*\." + re.escape(domain) + r")"
    for key, value in (headers or {}).items():
        for candidate in re.findall(pattern, str(value), re.I):
            cleaned = _clean(candidate, domain)
            if cleaned:
                yield cleaned, f"header: {key.lower()}"


# ══════════════════════════════════════════════════════════════════════════════
#  Reverse lookups
# ══════════════════════════════════════════════════════════════════════════════


def from_reverse_ip(domain: str) -> Iterator[Hit]:
    """Ask free reverse-IP services what else lives on the target's addresses.

    Sibling hostnames on the same server frequently resolve to an address the
    CDN does not front, which is exactly the leak being hunted.
    """
    from origintrace import probe

    for ip in probe.resolve(domain, "A")[:2]:
        body = _http(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if not body or "error" in body.lower()[:40]:
            continue
        for candidate in body.splitlines()[:60]:
            cleaned = _clean(candidate, domain)
            if cleaned:
                yield cleaned, f"reverse-ip: {ip}"


def from_cert_san_expansion(domain: str) -> Iterator[Hit]:
    """Read the *baseline's own* certificate for sibling names.

    Cheaper and more precise than crt.sh for the common case: the certificate the
    public site already serves lists everything on the same deployment.
    """
    from origintrace import probe

    for ip in probe.resolve(domain, "A")[:1]:
        cert = probe.certificate(ip, domain)
        if not cert.ok:
            continue
        for name in cert.sans:
            cleaned = _clean(name, domain)
            if cleaned:
                yield cleaned, f"cert-san: from {ip}"


# ══════════════════════════════════════════════════════════════════════════════
#  Registry
# ══════════════════════════════════════════════════════════════════════════════


PASSIVE_SOURCES: List[Tuple[str, str, object]] = [
    ("spf", "SPF record entries", from_spf),
    ("dmarc", "DMARC reporting hosts", from_dmarc),
    ("txt", "TXT verification hosts", from_txt_verification),
    ("robots", "robots.txt hostnames", from_robots),
    ("sitemap", "sitemap.xml hostnames", from_sitemap),
    ("csp", "CSP trusted origins", None),        # needs headers, driven by pipeline
    ("cert-san", "sibling names on the site certificate", from_cert_san_expansion),
    ("reverse-ip", "reverse-IP siblings", from_reverse_ip),
    ("wayback", "archived hostnames", from_wayback),
]


def describe() -> List[Tuple[str, str]]:
    """``(name, purpose)`` for ``--sources`` output and the docs."""
    return [(name, purpose) for name, purpose, _ in PASSIVE_SOURCES]
