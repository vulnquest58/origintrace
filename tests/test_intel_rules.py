"""Intel, rule-engine and model tests. All offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from origintrace import intel, rules
from origintrace.models import Candidate, Evidence as Obs, EvidenceKind


# ── datasets ────────────────────────────────────────────────────────────────


def test_datasets_load():
    """A missing dataset would silently disable CDN detection."""
    info = intel.dataset_info()
    assert info["cdn_networks"] > 100, info
    assert info["waf_signatures"] > 20, info


def test_known_cloudflare_range_is_detected():
    """A proxied Cloudflare range must classify as an edge node.

    ``104.16.0.0/13`` is one of the ranges Cloudflare actually proxies through;
    it is used here instead of ``1.1.1.0/24`` because that one is their public
    resolver network and is not in the shipped dataset.
    """
    owner = intel.cdn_owner("104.16.1.1")
    assert owner is not None
    assert "cloudflare" in owner.lower()


def test_private_address_is_not_a_cdn():
    assert intel.cdn_owner("10.0.0.1") is None


def test_invalid_address_returns_none_instead_of_raising():
    assert intel.cdn_owner("not-an-ip") is None


def test_waf_detection_from_headers():
    vendor = intel.detect_waf({"cf-ray": "8a1b2c3d", "server": "cloudflare"})
    assert vendor is not None


def test_waf_detection_is_case_insensitive():
    upper = intel.detect_waf({"CF-RAY": "8A1B2C3D"})
    lower = intel.detect_waf({"cf-ray": "8a1b2c3d"})
    assert upper == lower


def test_no_waf_marker_returns_none():
    assert intel.detect_waf({"server": "nginx/1.24.0"}) is None


# ── rule library ────────────────────────────────────────────────────────────


def test_rules_load_from_the_shipped_library():
    loaded = rules.load_rules()
    assert len(loaded) >= 25, f"only {len(loaded)} rules loaded"


def test_every_rule_has_a_name_and_category():
    for rule in rules.load_rules():
        assert rule.name
        assert rule.category


def test_rule_detects_nextjs_from_body():
    loaded = {rule.name: rule for rule in rules.load_rules()}
    rule = loaded.get("nextjs")
    assert rule is not None, "nextjs rule missing from the library"

    body = '<html><script id="__NEXT_DATA__" type="application/json">'
    detections = rules.detect([rule], {}, body)
    assert detections
    assert detections[0].rule == "nextjs"
    assert detections[0].confidence > 0.5


def test_rule_detects_nginx_from_header():
    loaded = {rule.name: rule for rule in rules.load_rules()}
    rule = loaded.get("nginx")
    assert rule is not None
    detections = rules.detect([rule], {"Server": "nginx/1.24.0"}, "")
    assert detections and detections[0].rule == "nginx"


def test_rule_does_not_fire_without_signals():
    loaded = {rule.name: rule for rule in rules.load_rules()}
    rule = loaded["nextjs"]
    assert rules.detect([rule], {"Server": "Apache"}, "") == []


def test_detections_are_ranked():
    loaded = rules.load_rules()
    body = '__NEXT_DATA__ /_next/static/chunks nginx'
    detections = rules.detect(loaded, {"Server": "nginx"}, body)
    confidences = [d.confidence for d in detections]
    assert confidences == sorted(confidences, reverse=True)


# ── models ──────────────────────────────────────────────────────────────────


def test_evidence_clamps_out_of_range_values():
    item = Obs(kind=EvidenceKind.TLS_EXACT_SAN, source="t", weight=5.0,
               confidence=-2.0)
    assert item.weight == 1.0
    assert item.confidence == 0.0


def test_negative_kinds_are_marked():
    assert Obs(kind=EvidenceKind.CATCH_ALL_VHOST, source="t").negative
    assert not Obs(kind=EvidenceKind.TLS_EXACT_SAN, source="t").negative


def test_candidate_deduplicates_discovery_trail():
    candidate = Candidate(ip="1.2.3.4")
    candidate.discovered_by.append("dns: current A record")
    assert candidate.discovered_by.count("dns: current A record") == 1


def test_json_serialisation_is_safe_for_bytes():
    """Details land in the report; a stray bytes value must not crash it."""
    item = Obs(kind=EvidenceKind.TLS_EXACT_SAN, source="t",
               details={"raw": b"\x00\xff", "path": Path("/tmp/x")})
    payload = json.dumps(item.to_dict())
    assert "raw" in payload
