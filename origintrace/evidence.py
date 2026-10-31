"""Scoring: turn observations into a verdict.

This is the part of origintrace that replaces "here are 40 IPs, good luck". The
rules are deliberately simple to read and easy to argue with, because an operator
who disagrees with a verdict must be able to see exactly which number produced
it.

Three things make the output trustworthy:

1. **Saturation, not addition.** Independent signals overlap — a matching
   certificate and a matching favicon both mean "same server" and adding them
   linearly overstates the case. Scores combine with
   ``1 - prod(1 - w_i)`` so ten weak signals can never outvote one decisive one,
   and a single strong signal cannot be pushed past 1.0 by noise.
2. **Weights are declared, not scattered.** Every kind lives in
   :data:`WEIGHTS`; there is no arithmetic in the modules.
3. **Negative evidence is subtractive and named.** A catch-all vhost is not the
   absence of proof, it is disproof, and the report says so.

See ``docs/EVIDENCE-MODEL.md`` for the empirical reasoning behind each weight.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from origintrace.models import (
    Candidate,
    Evidence,
    EvidenceKind,
    OriginType,
    Verdict,
)

# ══════════════════════════════════════════════════════════════════════════════
#  Weights
# ══════════════════════════════════════════════════════════════════════════════

#: Contribution of each observation kind, in the range 0..1.
#:
#: Grouping is intentional: identity signals (a certificate naming the domain)
#: outrank behavioural ones (the page looks similar), because behaviour can be
#: imitated by a parked page while a valid certificate for the name cannot.
WEIGHTS: Dict[EvidenceKind, float] = {
    # ── identity ────────────────────────────────────────────────────────────
    EvidenceKind.TLS_EXACT_SAN: 0.92,
    EvidenceKind.TLS_SAN_MATCH: 0.80,
    EvidenceKind.TLS_WILDCARD_SAN: 0.55,
    EvidenceKind.TLS_CERT_REUSED: 0.45,
    EvidenceKind.TLS_JARM_MATCH: 0.60,
    # ── behaviour ───────────────────────────────────────────────────────────
    EvidenceKind.VHOST_IDENTICAL: 0.75,
    EvidenceKind.CONTENT_SIMILAR: 0.50,
    EvidenceKind.TITLE_MATCH: 0.35,
    EvidenceKind.FAVICON_MATCH: 0.58,
    EvidenceKind.HEADER_FINGERPRINT_MATCH: 0.40,
    EvidenceKind.ETAG_MATCH: 0.30,
    EvidenceKind.REDIRECT_CHAIN_MATCH: 0.35,
    # ── provenance (where the IP came from) ─────────────────────────────────
    EvidenceKind.CERT_TRANSPARENCY: 0.30,
    EvidenceKind.PASSIVE_DNS_HISTORY: 0.28,
    EvidenceKind.SPF_OR_MX_LEAK: 0.22,
    EvidenceKind.SUBDOMAIN_UNIQUE_IP: 0.20,
    EvidenceKind.OPERATOR_SUPPLIED: 0.10,
    # ── classification (informational, near-zero pull) ──────────────────────
    EvidenceKind.HOSTED_ON_CDN: 0.0,
    EvidenceKind.BEHIND_WAF: 0.0,
    EvidenceKind.DEFAULT_PAGE: 0.0,
    # ── disqualifiers (subtracted, see NEGATIVE_KINDS) ──────────────────────
    EvidenceKind.CATCH_ALL_VHOST: 0.85,
    EvidenceKind.GENERIC_PARKING_PAGE: 0.80,
    EvidenceKind.CHALLENGE_PAGE: 0.70,
    EvidenceKind.UNREACHABLE: 0.90,
    EvidenceKind.SHARED_HOSTING: 0.25,
}

#: A verdict needs at least this much combined evidence before it is allowed to
#: name an origin. Chosen so that no single provenance signal can carry a
#: candidate on its own.
ORIGIN_THRESHOLD = 0.60

#: Below this the candidate is rejected outright rather than reported as
#: uncertain, which keeps the output free of "maybe" rows.
REJECT_THRESHOLD = 0.18


def _saturate(positive: List[float]) -> float:
    """Combine independent positive weights without overstating them.

    ``1 - prod(1 - w)``: three signals of 0.5 give 0.875, not 1.5. The result is
    monotonic and bounded in [0, 1], which is what lets the threshold mean
    something stable.
    """
    product = 1.0
    for weight in positive:
        product *= 1.0 - max(0.0, min(1.0, weight))
    return 1.0 - product


def _flatten(candidate: Candidate) -> Tuple[List[float], List[float], List[str]]:
    """Split a candidate's evidence into (positive, negative, reasons)."""
    positive: List[float] = []
    negative: List[float] = []
    reasons: List[str] = []

    for item in candidate.evidence:
        if item.kind not in WEIGHTS:
            # A module used a kind that has no declared weight. Treating it as
            # zero silently is worse than saying so, so it becomes a reason.
            reasons.append(f"{item.kind.value}: unweighted observation ignored")
            continue

        declared = WEIGHTS[item.kind]
        # The observation's own confidence modulates the declared weight; a
        # module may not inflate a weight beyond what the table allows.
        magnitude = declared * item.confidence

        if item.negative:
            negative.append(magnitude)
            reasons.append(f"- {item.kind.value} ({magnitude:.2f})")
        elif declared > 0:
            positive.append(magnitude)
            reasons.append(f"+ {item.kind.value} ({magnitude:.2f})")

    return positive, negative, reasons


def classify(candidate: Candidate, score: float) -> OriginType:
    """Decide what kind of host the candidate is, given its final score.

    Order matters: a confirmed CDN edge is an edge no matter how similar its
    content looks, because the similarity is the CDN doing its job.
    """
    if candidate.is_cdn or candidate.is_cdn is None and candidate.cdn_name:
        return OriginType.EDGE_NODE

    if candidate.has(EvidenceKind.UNREACHABLE):
        return OriginType.REJECTED

    if candidate.has(EvidenceKind.CATCH_ALL_VHOST) and score < ORIGIN_THRESHOLD:
        return OriginType.REJECTED

    if score >= ORIGIN_THRESHOLD:
        # Still shielded => report it, but as protected. Conflating this with an
        # exposed origin is the classic false positive.
        if candidate.is_waf or candidate.has(EvidenceKind.BEHIND_WAF):
            return OriginType.PROTECTED_ORIGIN
        if candidate.has(EvidenceKind.SHARED_HOSTING) and score < 0.80:
            return OriginType.SHADOW_ORIGIN
        return OriginType.EXPOSED_ORIGIN

    if score >= REJECT_THRESHOLD:
        return OriginType.UNCERTAIN

    return OriginType.REJECTED


def score(candidate: Candidate) -> Verdict:
    """Score one candidate and explain the result."""
    positive, negative, reasons = _flatten(candidate)

    combined = _saturate(positive) if positive else 0.0
    # Negative evidence is capped at the positive total: a candidate with no
    # supporting signal floors at 0 rather than going arbitrarily negative.
    penalty = min(combined, sum(negative))
    total = max(0.0, combined - penalty)

    if penalty:
        reasons.append(f"net {total:.2f} after {penalty:.2f} of disqualifiers")

    verdict = Verdict(candidate=candidate, score=total)
    verdict.origin_type = classify(candidate, total)
    verdict.reasons = reasons
    return verdict


def score_all(candidates: List[Candidate]) -> List[Verdict]:
    """Score every candidate, best first."""
    verdicts = [score(candidate) for candidate in candidates]
    verdicts.sort(key=lambda item: item.score, reverse=True)
    return verdicts


def explain(candidate: Candidate) -> str:
    """Human-readable breakdown, used by ``--explain`` and the tests."""
    verdict = score(candidate)
    lines = [
        f"{candidate.ip} -> {verdict.origin_type.value} "
        f"(score {verdict.score:.2f}, confidence {verdict.confidence:.0f}/100)"
    ]
    for reason in verdict.reasons:
        lines.append(f"    {reason}")
    return "\n".join(lines)
