"""Discovery: produce candidate IPs without touching the target.

Every source here is passive — it asks a third party "what do you know about
this name", never the target itself. That keeps discovery fast, quiet, and
inside the rules of most bounty programs even ones that forbid active scanning.

A source is a callable returning ``(ip, detail)`` pairs. Sources fail
independently: one dead API must not abort the scan, it becomes a warning.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Iterator, List, Set, Tuple

from origintrace import probe

logger = logging.getLogger("origintrace.discover")

#: ``(ip, detail)`` — the detail lands in the evidence trail.
Hit = Tuple[str, str]


@dataclass
class Source:
    """A named discovery source."""

    name: str
    collect: Callable[[str], Iterable[Hit]]
    enabled: bool = True


def _http_json(url: str, timeout: float = 8.0):
    """Plain GET returning parsed JSON, or ``None``.

    ``trust_env=False`` matters: a corporate proxy would otherwise silently
    answer for any host, and the tool would report the proxy's IP as an origin.
    """
    try:
        import httpx
        with httpx.Client(timeout=timeout, trust_env=False,
                          headers={"User-Agent": "origintrace/1.0"}) as client:
            response = client.get(url)
            if response.status_code != 200:
                return None
            return response.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("source request failed %s: %s", url, exc)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Sources
# ══════════════════════════════════════════════════════════════════════════════


def from_dns(domain: str) -> Iterator[Hit]:
    """Current A records. Not an origin, but the reference point."""
    for ip in probe.resolve(domain, "A"):
        yield ip, "current A record"


def from_certificate_transparency(domain: str) -> Iterator[Hit]:
    """crt.sh: certificates issued for the name often name an origin host.

    Only *hostnames* are returned, not IPs — the caller resolves them. Entries
    are filtered to the target's own suffix so a shared host's unrelated
    certificates do not leak in.
    """
    data = _http_json(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not isinstance(data, list):
        return
    seen: Set[str] = set()
    for row in data[:400]:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen or not name.endswith(domain):
                continue
            seen.add(name)
            for ip in probe.resolve(name, "A")[:2]:
                yield ip, f"ct: {name}"


def from_mx(domain: str) -> Iterator[Hit]:
    """Mail exchangers usually bypass the CDN, which is why they leak origins."""
    for host in probe.mx_hosts(domain):
        for ip in probe.resolve(host, "A")[:3]:
            yield ip, f"mx: {host}"


def from_subdomains(domain: str, names: Iterable[str]) -> Iterator[Hit]:
    """Resolve operator-supplied (or wordlist) subdomains."""
    for name in names:
        candidate = name if name.endswith(domain) else f"{name}.{domain}"
        for ip in probe.resolve(candidate, "A")[:3]:
            yield ip, f"subdomain: {candidate}"


def from_shodan_internetdb(domain: str) -> Iterator[Hit]:
    """Shodan InternetDB: free, keyless, and returns hostnames per IP.

    It is used in reverse here: resolve the current A records, then ask which
    *other* hostnames share those IPs, then resolve those hostnames. That finds
    sibling origins without any paid passive-DNS feed.
    """
    for ip in probe.resolve(domain, "A")[:3]:
        data = _http_json(f"https://internetdb.shodan.io/{ip}")
        if not isinstance(data, dict):
            continue
        for hostname in (data.get("hostnames") or [])[:20]:
            hostname = str(hostname).lower()
            if not hostname.endswith(domain):
                continue
            for resolved in probe.resolve(hostname, "A")[:3]:
                if resolved != ip:
                    yield resolved, f"internetdb: {hostname}"


DEFAULT_SOURCES: List[Source] = [
    Source("dns", from_dns),
    Source("mx", from_mx),
    Source("ct", from_certificate_transparency),
    Source("internetdb", from_shodan_internetdb),
]


# ══════════════════════════════════════════════════════════════════════════════
#  Driver
# ══════════════════════════════════════════════════════════════════════════════


def discover(domain: str, sources: Iterable[Source] = (),
             subdomains: Iterable[str] = (),
             headers: dict | None = None,
             progress=None) -> Dict[str, List[str]]:
    """Run every enabled source and return ``{ip: [details]}``.

    Duplicates are merged so one IP reached from three sources is remembered
    once with all three trail entries — the count of independent sources is
    itself a weak signal, and merging preserves it.

    ``progress`` is called as ``progress(name, found_count, error_or_empty)``
    after each source, so the CLI can print results the moment a source returns
    instead of waiting for the slowest one.
    """
    chosen = list(sources) or list(DEFAULT_SOURCES)
    if subdomains:
        chosen.append(Source("subdomains",
                             lambda d: from_subdomains(d, subdomains)))

    found: Dict[str, List[str]] = {}
    hostnames: List[Tuple[str, str]] = []
    blocked: List[str] = []

    for source in chosen:
        if not source.enabled:
            continue
        before = len(found)
        try:
            for value, detail in source.collect(domain):
                # Sources may return a hostname instead of an address; resolving
                # here keeps every source simple and puts DNS in one place.
                if _looks_like_ip(value):
                    if not is_probeable(value):
                        # Never probe the operator's own network, however the
                        # address was discovered.
                        if value not in blocked:
                            blocked.append(value)
                        continue
                    found.setdefault(value, []).append(f"{source.name}: {detail}")
                else:
                    hostnames.append((value, f"{source.name}: {detail}"))
            if progress:
                progress(source.name, len(found) - before, "")
        except Exception as exc:  # noqa: BLE001 - one source must not kill the run
            logger.warning("source %s failed: %s", source.name, exc)
            if progress:
                progress(source.name, len(found) - before, str(exc)[:80])

    # Resolve every hostname discovered above, in one pass.
    for host, trail in _unique(hostnames):
        for ip in probe.resolve(host, "A")[:3]:
            if not _looks_like_ip(ip):
                continue
            if not is_probeable(ip):
                if ip not in blocked:
                    blocked.append(ip)
                continue
            found.setdefault(ip, []).append(trail)

    if blocked:
        logger.info("skipped %d non-routable address(es): %s",
                    len(blocked), ", ".join(blocked[:5]))
    found.pop("__warnings__", None)
    return found


def _unique(pairs: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Drop duplicate hostnames while keeping the first explanation for each."""
    seen: Set[str] = set()
    result: List[Tuple[str, str]] = []
    for host, trail in pairs:
        if host in seen:
            continue
        seen.add(host)
        result.append((host, trail))
    return result


def extended_sources(headers: dict) -> List[Source]:
    """The advanced passive sources, wired to the baseline response headers.

    They live here rather than in :data:`DEFAULT_SOURCES` because most of them
    make an outbound request to a third party, which should be a deliberate
    choice on a scan of a live target.
    """
    from origintrace import sources as advanced

    wired: List[Source] = []
    for name, _purpose, collector in advanced.PASSIVE_SOURCES:
        if collector is None:
            continue
        wired.append(Source(name, collector))

    if headers:
        wired.append(Source(
            "csp",
            lambda domain: advanced.from_csp(headers, domain),
        ))
        wired.append(Source(
            "headers",
            lambda domain: advanced.from_headers_generic(headers, domain),
        ))
    return wired


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def is_probeable(ip: str) -> bool:
    """False for addresses that must never be probed.

    A passive source can leak an internal hostname (``10.32.10.95`` from an MX
    record, a CT entry for a pre-CDN staging name). Probing that address would
    send traffic to **the operator's own network** — useless as evidence and
    actively harmful. Private, loopback, link-local, multicast, reserved and
    unspecified ranges are therefore dropped at discovery time, and the drop is
    reported rather than hidden.
    """
    import ipaddress

    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


#: Subdomain wordlist kept short on purpose: this is a hint generator, not a
#: bruteforcer. Large lists belong in a real recon tool, not in an origin check.
COMMON_HINTS: List[str] = [
    "direct", "origin", "origin-www", "internal", "backend", "staging",
    "dev", "test", "old", "legacy", "mail", "webmail", "smtp", "vpn",
    "admin", "portal", "api-internal", "ftp", "cpanel", "server1",
]
