"""Evidence-model tests: the scoring rules are the product, so they get pinned.

Every test here is offline and deterministic. If a weight changes, these fail —
which is the point: a silent weight change would alter every verdict the tool
ever produces.
"""

from __future__ import annotations

import math

import pytest

from origintrace import evidence
from origintrace.models import (
    Candidate,
    Evidence as Obs,
    EvidenceKind,
    OriginType,
)


def make(ip: str = "203.0.113.9", **evidence_kwargs) -> Candidate:
    candidate = Candidate(ip=ip)
    for kind, confidence in evidence_kwargs.items():
        candidate.add(Obs(kind=kind, source="test", confidence=confidence))
    return candidate


# ── saturation ──────────────────────────────────────────────────────────────


def test_saturating_combination_never_exceeds_one():
    """Ten strong signals must not produce a score above 1.0."""
    candidate = Candidate(ip="203.0.113.9")
    for _ in range(10):
        candidate.add(Obs(kind=EvidenceKind.VHOST_IDENTICAL, source="t",
                          confidence=1.0))
    verdict = evidence.score(candidate)
    assert verdict.score <= 1.0


def test_one_decisive_signal_clears_the_origin_threshold():
    """A cert naming the domain is enough on its own — by design."""
    verdict = evidence.score(make(tls_exact_san=1.0))
    assert verdict.score >= evidence.ORIGIN_THRESHOLD
    assert verdict.origin_type is OriginType.EXPOSED_ORIGIN


def test_weak_signals_alone_do_not_name_an_origin():
    """Provenance hints are evidence, not proof."""
    candidate = Candidate(ip="203.0.113.9")
    candidate.add(Obs(kind=EvidenceKind.SUBDOMAIN_UNIQUE_IP, source="t",
                      confidence=1.0))
    candidate.add(Obs(kind=EvidenceKind.OPERATOR_SUPPLIED, source="t",
                      confidence=1.0))
    verdict = evidence.score(candidate)
    assert verdict.score < evidence.ORIGIN_THRESHOLD
    assert verdict.origin_type is not OriginType.EXPOSED_ORIGIN


def test_confidence_scales_the_declared_weight():
    """A 50%-confident observation contributes half of the declared weight."""
    full = evidence.score(make(favicon_match=1.0)).score
    half = evidence.score(
        make(favicon_match=0.0, **{})
    ).score if False else None
    # Build the half-confidence case explicitly to keep the assertion obvious.
    candidate = Candidate(ip="203.0.113.9")
    candidate.add(Obs(kind=EvidenceKind.FAVICON_MATCH, source="t",
                      confidence=0.5))
    half = evidence.score(candidate).score
    assert math.isclose(half, full / 2, rel_tol=1e-9)


# ── negative evidence ───────────────────────────────────────────────────────


def test_catch_all_vhost_kills_a_content_match():
    """The classic false positive: a server that answers for any hostname."""
    candidate = Candidate(ip="203.0.113.9")
    candidate.add(Obs(kind=EvidenceKind.VHOST_IDENTICAL, source="t",
                      confidence=1.0))
    candidate.add(Obs(kind=EvidenceKind.CATCH_ALL_VHOST, source="t",
                      confidence=1.0))
    verdict = evidence.score(candidate)
    assert verdict.score < evidence.ORIGIN_THRESHOLD
    assert verdict.origin_type is not OriginType.EXPOSED_ORIGIN


def test_negative_evidence_cannot_go_below_zero():
    candidate = Candidate(ip="203.0.113.9")
    for kind in (EvidenceKind.CATCH_ALL_VHOST, EvidenceKind.UNREACHABLE,
                 EvidenceKind.GENERIC_PARKING_PAGE):
        candidate.add(Obs(kind=kind, source="t", confidence=1.0))
    assert evidence.score(candidate).score >= 0.0


def test_unreachable_is_rejected_outright():
    candidate = Candidate(ip="203.0.113.9")
    candidate.add(Obs(kind=EvidenceKind.UNREACHABLE, source="t",
                      confidence=1.0))
    assert evidence.score(candidate).origin_type is OriginType.REJECTED


# ── classification ──────────────────────────────────────────────────────────


def test_cdn_edge_is_never_an_origin_however_similar():
    """A CDN answers for thousands of sites; similarity there means nothing."""
    candidate = make(tls_exact_san=1.0, vhost_identical=1.0)
    candidate.is_cdn = True
    candidate.cdn_name = "Cloudflare"
    assert evidence.score(candidate).origin_type is OriginType.EDGE_NODE


def test_waf_still_up_means_protected_not_exposed():
    candidate = make(tls_exact_san=1.0, vhost_identical=1.0)
    candidate.is_cdn = False
    candidate.is_waf = True
    candidate.waf_name = "Cloudflare"
    assert evidence.score(candidate).origin_type is OriginType.PROTECTED_ORIGIN


def test_shared_hosting_with_moderate_score_is_shadow():
    """A real match on a shared host is a shadow, not an exposed origin.

    ``SHADOW_ORIGIN`` is the band between the origin threshold and 0.80: the IP
    does serve the site, but it also serves other tenants, so treating it as a
    clean bypass would overstate the finding.
    """
    candidate = Candidate(ip="203.0.113.9")
    for kind in (EvidenceKind.TLS_WILDCARD_SAN, EvidenceKind.FAVICON_MATCH,
                 EvidenceKind.TITLE_MATCH):
        candidate.add(Obs(kind=kind, source="test", confidence=1.0))
    candidate.is_cdn = False
    candidate.is_waf = False
    candidate.add(Obs(kind=EvidenceKind.SHARED_HOSTING, source="test",
                      confidence=1.0))

    verdict = evidence.score(candidate)
    assert evidence.ORIGIN_THRESHOLD <= verdict.score < 0.80, verdict.score
    assert verdict.origin_type is OriginType.SHADOW_ORIGIN


# ── properties ──────────────────────────────────────────────────────────────


def test_every_weight_is_a_probability():
    for kind, weight in evidence.WEIGHTS.items():
        assert 0.0 <= weight <= 1.0, f"{kind} weight out of range: {weight}"


def test_scoring_is_order_independent():
    a = Candidate(ip="1.1.1.1")
    b = Candidate(ip="1.1.1.1")
    observations = [
        Obs(kind=EvidenceKind.TLS_EXACT_SAN, source="t", confidence=1.0),
        Obs(kind=EvidenceKind.FAVICON_MATCH, source="t", confidence=0.5),
        Obs(kind=EvidenceKind.SHARED_HOSTING, source="t", confidence=1.0),
    ]
    for item in observations:
        a.add(item)
    for item in reversed(observations):
        b.add(item)

    assert math.isclose(evidence.score(a).score, evidence.score(b).score,
                        rel_tol=1e-12)


def test_verdict_carries_reasons_for_humans():
    verdict = evidence.score(make(tls_exact_san=1.0))
    assert verdict.reasons
    assert any(reason.startswith("+") for reason in verdict.reasons)


def test_explain_is_readable():
    text = evidence.explain(make(tls_exact_san=1.0))
    assert "203.0.113.9" in text
    assert "score" in text
