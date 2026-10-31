"""Validation: decide whether a candidate really serves the target.

This module is where false positives die. Each function answers one narrow
question and returns evidence rather than a boolean, so the report can show what
was checked even when nothing matched.

The four questions, in order of strength:

1. **Does the certificate name the domain?** Hard to fake, cheap to check.
2. **Does the IP serve the site when asked for this hostname?** The definition of
   an origin, and the test most tools skip.
3. **Is the content the same as the public site?** Supports a match but cannot
   prove one — parked pages and mirrors look identical too.
4. **Is it a catch-all?** A server answering *any* hostname with the real page is
   the single most common source of false "origin found" claims.
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

from origintrace import probe
from origintrace.models import Candidate, Evidence, EvidenceKind, ScanContext

logger = logging.getLogger("origintrace.validate")

#: Similarity above which two pages are considered "the same site". Below 0.60
#: the visual difference is usually a hosting provider's default page.
SAME_SITE_THRESHOLD = 0.78

#: Similarity below which a page is considered clearly different.
DIFFERENT_THRESHOLD = 0.45

#: Hostname used to test for a catch-all. It cannot resolve to the target, so any
#: "success" is the server answering everything — exactly what we look for.
CATCHALL_HOST = "origintrace-canary.invalid"


# ══════════════════════════════════════════════════════════════════════════════
#  Certificate identity
# ══════════════════════════════════════════════════════════════════════════════


def _domain_matches(pattern: str, domain: str) -> Tuple[bool, str]:
    """Match a certificate name against the target, returning (hit, kind)."""
    pattern = pattern.lower().strip().rstrip(".")
    domain = domain.lower().strip().rstrip(".")

    if pattern == domain:
        return True, "exact"
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # A wildcard covers exactly one label: *.example.com covers
        # a.example.com but not a.b.example.com.
        if domain.endswith("." + suffix) and domain.count(".") == suffix.count(".") + 1:
            return True, "wildcard"
    return False, ""


def tls_identity(candidate: Candidate, domain: str) -> List[Evidence]:
    """Collect certificate-based evidence for one candidate."""
    cert = probe.certificate(candidate.ip, domain)
    if not cert.ok:
        logger.debug("no certificate from %s: %s", candidate.ip, cert.error)
        return []

    found: List[Evidence] = []
    for name in cert.sans or ([cert.subject_cn] if cert.subject_cn else []):
        hit, kind = _domain_matches(name, domain)
        if not hit:
            continue
        if kind == "exact":
            found.append(Evidence(
                kind=EvidenceKind.TLS_EXACT_SAN,
                source="tls",
                confidence=1.0,
                details={"san": name, "issuer": cert.issuer},
            ))
            break
        found.append(Evidence(
            kind=EvidenceKind.TLS_WILDCARD_SAN,
            source="tls",
            confidence=1.0,
            details={"san": name, "issuer": cert.issuer},
        ))
        break

    if found:
        # A certificate is stronger when it was not self-signed: anyone can mint
        # one, but a public CA only issues for a name the requester controls.
        for item in found:
            item.details["self_signed"] = cert.self_signed
            item.details["expired"] = cert.expired
    return found


# ══════════════════════════════════════════════════════════════════════════════
#  Vhost behaviour
# ══════════════════════════════════════════════════════════════════════════════


def vhost_behaviour(candidate: Candidate, context: ScanContext) -> List[Evidence]:
    """Ask the candidate to serve the target's hostname, then judge the answer."""
    found: List[Evidence] = []

    response = probe.probe_vhost(candidate.ip, context.vhost)
    candidate.status_code = response.status
    candidate.title = response.title

    if not response.ok:
        found.append(Evidence(
            kind=EvidenceKind.UNREACHABLE,
            source="vhost",
            confidence=1.0,
            details={"error": response.error},
        ))
        return found

    # A challenge page is the WAF refusing to talk to us, not the origin.
    if _is_challenge(response):
        found.append(Evidence(
            kind=EvidenceKind.CHALLENGE_PAGE,
            source="vhost",
            confidence=0.9,
            details={"server": response.server, "status": response.status},
        ))
        return found

    if _is_catch_all(candidate.ip, context.vhost, response):
        found.append(Evidence(
            kind=EvidenceKind.CATCH_ALL_VHOST,
            source="vhost",
            confidence=1.0,
            details={"canary": CATCHALL_HOST,
                     "note": "server answers any hostname with this content"},
        ))
        return found

    similarity = similarity_to_baseline(response, context)

    if similarity >= SAME_SITE_THRESHOLD:
        found.append(Evidence(
            kind=EvidenceKind.VHOST_IDENTICAL,
            source="vhost",
            confidence=similarity,
            details={"similarity": round(similarity, 3),
                     "status": response.status},
        ))
    elif similarity >= DIFFERENT_THRESHOLD:
        found.append(Evidence(
            kind=EvidenceKind.CONTENT_SIMILAR,
            source="vhost",
            confidence=similarity,
            details={"similarity": round(similarity, 3)},
        ))
    else:
        found.append(Evidence(
            kind=EvidenceKind.DEFAULT_PAGE,
            source="vhost",
            confidence=1.0,
            details={"similarity": round(similarity, 3),
                     "title": response.title},
        ))

    if response.title and context.baseline_title and \
            response.title.strip().lower() == context.baseline_title.strip().lower():
        found.append(Evidence(
            kind=EvidenceKind.TITLE_MATCH,
            source="vhost",
            confidence=1.0,
            details={"title": response.title},
        ))

    if response.header_fingerprint() and \
            response.header_fingerprint() == context.stats.get("baseline_hfp"):
        found.append(Evidence(
            kind=EvidenceKind.HEADER_FINGERPRINT_MATCH,
            source="vhost",
            confidence=1.0,
        ))

    return found


def _is_challenge(response: probe.Response) -> bool:
    """Detect a CDN/WAF interstitial rather than real content."""
    server = (response.server or "").lower()
    body = (response.body or "")[:8192].lower()
    markers = (
        "just a moment", "checking your browser", "cloudflare",
        "attention required", "ddos protection by", "cf-browser-verification",
        "please enable javascript and cookies",
    )
    if response.status in (403, 429, 503) and any(m in body for m in markers):
        return True
    return "cloudflare" in server and any(m in body for m in markers)


def _is_catch_all(ip: str, vhost: str, real: probe.Response) -> bool:
    """Return True when the server serves the same page for an unknown host.

    Only a *matching* response to the canary counts: a 404 from the canary means
    the server is behaving correctly and the real response is meaningful.
    """
    canary = probe.probe_vhost(ip, CATCHALL_HOST)
    if not canary.ok or canary.status != real.status:
        return False
    if not real.body or not canary.body:
        return False
    return _ratio(real.body, canary.body) >= SAME_SITE_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
#  Content comparison
# ══════════════════════════════════════════════════════════════════════════════


def _ratio(left: str, right: str) -> float:
    """Similarity of two documents on a normalised body.

    ``difflib`` alone is too generous on short pages — "Acme / hello world" and
    "Parked / domain for sale" score 0.74 because they share HTML scaffolding,
    which would report a parked page as the real site. Blending in token overlap
    pulls genuinely different content down without hurting identical pages.
    """
    a, b = _normalise_body(left), _normalise_body(right)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    sequence = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()

    tokens_a, tokens_b = set(a.split()), set(b.split())
    union = tokens_a | tokens_b
    jaccard = len(tokens_a & tokens_b) / len(union) if union else 0.0

    return max(0.0, min(1.0, 0.5 * sequence + 0.5 * jaccard))


def _normalise_body(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip().lower()
    text = re.sub(r"[a-f0-9]{16,}", " ", text)      # hashes / nonces / ids
    text = re.sub(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}[^ ]*", " ", text)  # stamps
    text = re.sub(r"\b\d{10,13}\b", " ", text)     # epoch values
    return text[:6000]


def similarity_to_baseline(response: probe.Response,
                           context: ScanContext) -> float:
    """Compare a vhost response with the public baseline page."""
    if not context.baseline_body_hash:
        return 0.0
    baseline_body = context.stats.get("_baseline_body", "")
    if not baseline_body:
        # Baseline body was not retained; fall back to the stored hash, which can
        # only tell us "identical" or "not identical".
        return 1.0 if response.body_hash == context.baseline_body_hash else 0.0
    return _ratio(baseline_body, response.body)


def favicon(candidate: Candidate, context: ScanContext) -> Optional[Evidence]:
    """Favicon hashes survive CDNs and survive content changes — cheap and strong."""
    if not context.baseline_favicon:
        return None

    path = "/favicon.ico"
    response = probe.probe_vhost(candidate.ip, context.vhost)
    if not response.ok:
        return None

    import httpx
    try:
        with httpx.Client(timeout=6, verify=False, trust_env=False) as client:
            raw = client.get(
                f"http://{candidate.ip}{path}",
                headers={"Host": context.vhost},
            )
            if raw.status_code != 200 or not raw.content:
                return None
            digest = hashlib.sha256(raw.content).hexdigest()[:16]
    except Exception:  # noqa: BLE001
        return None

    if digest == context.baseline_favicon:
        return Evidence(
            kind=EvidenceKind.FAVICON_MATCH,
            source="favicon",
            confidence=1.0,
            details={"hash": digest},
        )
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Orchestration
# ══════════════════════════════════════════════════════════════════════════════


def validate(candidate: Candidate, context: ScanContext,
             with_tls: bool = True, with_favicon: bool = True) -> Candidate:
    """Run every validation check for one candidate and attach the evidence."""
    if with_tls:
        for item in tls_identity(candidate, context.target):
            candidate.add(item)

    for item in vhost_behaviour(candidate, context):
        candidate.add(item)

    if with_favicon and not candidate.has(EvidenceKind.CATCH_ALL_VHOST):
        item = favicon(candidate, context)
        if item:
            candidate.add(item)

    return candidate
