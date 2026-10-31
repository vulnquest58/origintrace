"""Infrastructure intelligence: is this IP an edge node or a real server?

Before an IP can be considered an origin, two questions must be answered:

* **Is it a CDN?** If yes, it is the thing we are trying to bypass, and no
  amount of content similarity makes it an origin.
* **Is it a WAF or a shared host?** Neither disqualifies the IP, but both change
  what the finding means, so they are recorded rather than guessed.

The datasets are plain JSON checked into the package so the tool works offline
and never depends on a third-party API key. They are refreshed out of band.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("origintrace.intel")

DATA_DIR = Path(__file__).resolve().parent / "data"

CDN_RANGES_FILE = DATA_DIR / "cdn_ip_ranges.json"
WAF_SIG_FILE = DATA_DIR / "waf_signatures.json"
#: Supplementary signatures that match on header *values* rather than names.
#: Kept separate so the ported dataset stays byte-identical to its source and the
#: provenance of every added rule is obvious.
WAF_EXTRA_FILE = DATA_DIR / "waf_signatures_extra.json"
HOSTING_FILE = DATA_DIR / "hosting_asns.json"


# ══════════════════════════════════════════════════════════════════════════════
#  CDN ranges
# ══════════════════════════════════════════════════════════════════════════════


@lru_cache(maxsize=1)
def _cdn_networks() -> Tuple[Tuple[str, object], ...]:
    """Load the CDN ranges once as ``(name, network)`` pairs.

    Malformed entries are skipped rather than fatal: a stale dataset must not
    take the whole scan down, but it is logged so the operator can refresh it.
    """
    pairs: List[Tuple[str, object]] = []
    if not CDN_RANGES_FILE.is_file():
        logger.warning("CDN dataset missing: %s", CDN_RANGES_FILE)
        return tuple()

    try:
        raw = json.loads(CDN_RANGES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.error("CDN dataset unreadable: %s", exc)
        return tuple()

    for name, ranges in raw.items():
        if not isinstance(ranges, list):
            continue
        for entry in ranges:
            try:
                pairs.append((name, ipaddress.ip_network(str(entry), strict=False)))
            except ValueError:
                # Country names sometimes appear in these files; ignore quietly.
                continue
    return tuple(pairs)


def cdn_owner(ip: str) -> Optional[str]:
    """Return the CDN that owns ``ip``, or ``None`` when it is not an edge node."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, network in _cdn_networks():
        if address.version == network.version and address in network:
            return name
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  WAF signatures
# ══════════════════════════════════════════════════════════════════════════════


@lru_cache(maxsize=1)
def _waf_signatures() -> Dict[str, dict]:
    """Load and merge the WAF signatures, metadata sections excluded.

    The base file matches header *names*; the overlay adds name+value pairs,
    because most vendors announce themselves in the value of ``server`` or
    ``via`` rather than in a distinctive header name. When both define the same
    vendor the lists are merged, with the overlay winning on conflict.
    """
    merged: Dict[str, dict] = {}

    for path in (WAF_SIG_FILE, WAF_EXTRA_FILE):
        if not path.is_file():
            logger.warning("WAF dataset missing: %s", path)
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.error("WAF dataset unreadable (%s): %s", path.name, exc)
            continue
        if not isinstance(raw, dict):
            continue
        cleaned = {
            key: value
            for key, value in raw.items()
            if key != "metadata" and isinstance(value, dict)
        }
        merged = _merge_waf(merged, cleaned)

    return merged


def _merge_waf(base: Dict[str, dict], extra: Dict[str, dict]) -> Dict[str, dict]:
    """Union two signature maps, concatenating the per-vendor lists."""
    result = {key: dict(value) for key, value in base.items()}

    for vendor, spec in extra.items():
        if vendor == "metadata" or not isinstance(spec, dict):
            continue
        target = result.setdefault(vendor, {"name": spec.get("name", vendor)})
        for field in ("headers", "header_values", "cookies",
                      "body_signatures", "response_codes"):
            incoming = spec.get(field)
            if not incoming:
                continue
            existing = target.get(field) or []
            combined = list(existing)
            for item in incoming:
                if item not in combined:
                    combined.append(item)
            target[field] = combined
        for field in ("name", "vendor", "type", "description"):
            if spec.get(field) and not target.get(field):
                target[field] = spec[field]
    return result


def detect_waf(headers: Dict[str, str], cookies: Iterable[str] = (),
               body: str = "") -> Optional[str]:
    """Identify a WAF from response headers, cookies or body markers.

    Matching is case-insensitive and substring-based on purpose: vendors
    decorate their headers (``cf-ray``, ``CF-RAY``, ``x-cf-ray``) and an exact
    match would silently miss them.

    Every vendor's rules are *scored* and the strongest match wins, rather than
    returning the first hit. This matters because several vendors share generic
    block-page text ("Access Denied"), and first-match-wins attributed a Sucuri
    block page to F5 — a wrong finding is worse than no finding.
    """
    lowered = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    cookie_blob = " ".join(str(c).lower() for c in cookies)
    body_lower = (body or "")[:8192].lower()

    best_vendor = None
    best_score = 0

    for vendor, spec in _waf_signatures().items():
        score = _score_vendor(spec, lowered, cookie_blob, body_lower)
        if score > best_score:
            best_score, best_vendor = score, vendor

    return best_vendor


#: Markers too generic to identify a vendor on their own. They still count, but
#: only when the same vendor's specific rules also fire.
GENERIC_MARKERS = frozenset({
    "access denied", "request blocked", "the requested url was rejected",
    "forbidden", "blocked",
})


def _score_vendor(spec: dict, lowered: Dict[str, str], cookie_blob: str,
                  body_lower: str) -> int:
    """Specificity score for one vendor. Higher is a stronger identification."""
    score = 0

    for header in spec.get("headers", []) or []:
        if isinstance(header, dict):
            name = str(header.get("name", "")).lower()
            pattern = str(header.get("pattern", "")).lower()
        else:
            name, pattern = str(header).lower(), ""
        if name and name in lowered and (not pattern or pattern in lowered[name]):
            score += 10

    for rule in spec.get("header_values", []) or []:
        if not isinstance(rule, dict):
            continue
        name = str(rule.get("name", "")).lower()
        pattern = str(rule.get("pattern", "")).lower()
        if not name or name not in lowered:
            continue
        if not pattern or pattern in lowered[name]:
            score += 8

    for cookie in spec.get("cookies", []) or []:
        if str(cookie).lower() in cookie_blob:
            score += 6

    for marker in spec.get("body_signatures", []) or []:
        text = str(marker).lower()
        if not text or text not in body_lower:
            continue
        score += 3 if text in GENERIC_MARKERS else 5

    return score


def detect_waf_from_blob(headers: Dict[str, str]) -> Optional[str]:
    """Header-only convenience wrapper used by the fast probe path."""
    return detect_waf(headers)


# ══════════════════════════════════════════════════════════════════════════════
#  Hosting / shared infrastructure
# ══════════════════════════════════════════════════════════════════════════════


@lru_cache(maxsize=1)
def _hosting_asns() -> Dict[str, str]:
    """Map ``AS12345`` -> provider name for shared hosting networks."""
    if not HOSTING_FILE.is_file():
        return {}
    try:
        raw = json.loads(HOSTING_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

    mapping: Dict[str, str] = {}
    # Tolerate every shape seen in the source dataset: a flat map, a map of
    # provider -> [asns], or provider -> {asns: [...]}. ASNs arrive as integers
    # there, so they are normalised to the ``ASnnn`` form used everywhere else.
    for key, value in raw.items():
        if key == "metadata":
            continue
        if isinstance(value, list):
            for asn in value:
                normalised = _as_asn(asn)
                if normalised:
                    mapping[normalised] = str(key)
        elif isinstance(value, dict) and "asns" in value:
            provider = str(value.get("name", key))
            for asn in value.get("asns") or []:
                normalised = _as_asn(asn)
                if normalised:
                    mapping[normalised] = provider
        elif str(key).upper().startswith("AS"):
            normalised = _as_asn(key)
            if normalised:
                mapping[normalised] = str(value)
    return mapping


def _as_asn(value: object) -> str:
    """Normalise ``16509`` / ``'16509'`` / ``'AS16509'`` to ``AS16509``."""
    text = str(value).strip().upper()
    if not text:
        return ""
    if text.startswith("AS"):
        text = text[2:]
    return f"AS{text}" if text.isdigit() else ""


def hosting_provider(asn: str) -> Optional[str]:
    """Return the shared-hosting provider for an ASN, if it is one."""
    if not asn:
        return None
    return _hosting_asns().get(str(asn).upper())


# ══════════════════════════════════════════════════════════════════════════════
#  Reporting helper
# ══════════════════════════════════════════════════════════════════════════════


def classify_ip(ip: str) -> Dict[str, Optional[str]]:
    """Bundle the three classifications for one address."""
    owner = cdn_owner(ip)
    return {
        "cdn": owner,
        "ip_version": str(ipaddress.ip_address(ip).version)
        if _is_ip(ip) else None,
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def dataset_info() -> Dict[str, int]:
    """Counts used by ``origintrace --datasets`` and the tests."""
    return {
        "cdn_networks": len(_cdn_networks()),
        "waf_signatures": len(_waf_signatures()),
        "hosting_asns": len(_hosting_asns()),
    }
