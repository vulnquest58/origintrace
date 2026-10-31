"""Pipeline, validation and report tests.

Network is replaced by fakes, so these run in CI and prove the decision logic
rather than the internet connection.
"""

from __future__ import annotations

import json

import pytest

from origintrace import pipeline, probe, report, validate
from origintrace.models import (
    Candidate,
    Evidence,
    EvidenceKind,
    OriginType,
    ScanContext,
)


# â”€â”€ fakes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def make_response(body: str = "<html><title>Acme</title></html>",
                  status: int = 200, headers: dict | None = None) -> probe.Response:
    return probe.Response(url="http://x/", status=status,
                          headers=headers or {"Server": "nginx"},
                          body=body)


def make_context(target: str = "example.com") -> ScanContext:
    context = ScanContext(target=target)
    context.baseline_title = "Acme"
    context.baseline_status = 200
    context.baseline_body_hash = make_response().body_hash
    setattr(context, "_baseline_body", make_response().body)
    return context


# â”€â”€ certificate matching (pure logic) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@pytest.mark.parametrize("pattern,domain,expected", [
    ("example.com", "example.com", True),
    ("example.com", "www.example.com", False),
    ("*.example.com", "www.example.com", True),
    ("*.example.com", "a.b.example.com", False),
    ("*.example.com", "example.com", False),
    ("EXAMPLE.COM", "example.com", True),
])
def test_domain_matching(pattern, domain, expected):
    hit, _ = validate._domain_matches(pattern, domain)
    assert hit is expected


def test_wildcard_is_reported_as_wildcard_not_exact():
    _, kind = validate._domain_matches("*.example.com", "www.example.com")
    assert kind == "wildcard"


# â”€â”€ content similarity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_identical_pages_score_one():
    a = "<html><title>Acme</title><body>hello</body></html>"
    assert validate._ratio(a, a) > 0.99


def test_different_pages_score_low():
    a = "<html><title>Acme</title>hello world</html>"
    b = "<html><title>Parked</title>domain for sale</html>"
    assert validate._ratio(a, b) < validate.DIFFERENT_THRESHOLD


def test_dynamic_tokens_do_not_reduce_similarity():
    """A nonce must not make two requests to the same server look different."""
    a = "<html>token=deadbeef12345678 ts=2026-01-01T00:00:00Z content</html>"
    b = "<html>token=cafebabe87654321 ts=2026-02-02T11:11:11Z content</html>"
    assert validate._ratio(a, b) > 0.85


def test_challenge_page_is_detected():
    response = probe.Response(
        status=403,
        headers={"Server": "cloudflare"},
        body="<html>Just a moment... checking your browser</html>",
    )
    assert validate._is_challenge(response)


def test_ordinary_403_is_not_a_challenge_page():
    response = probe.Response(status=403, headers={"Server": "nginx"},
                              body="<html>Forbidden</html>")
    assert not validate._is_challenge(response)


# â”€â”€ classification via pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_pipeline_marks_cdn_addresses_and_skips_probing(monkeypatch):
    """An edge node must not be probed: it answers for thousands of sites."""
    context = make_context()

    monkeypatch.setattr(pipeline.probe, "baseline",
                        lambda *a, **k: make_response())
    # Discovery is faked to return a known Cloudflare address.
    monkeypatch.setattr(pipeline.discovery, "discover",
                        lambda *a, **k: {"104.16.1.1": ["dns: current A record"]})

    probed: list[str] = []
    monkeypatch.setattr(pipeline.validate, "validate",
                        lambda cand, ctx, **k: probed.append(cand.ip) or cand)

    pipeline.run(context, pipeline.Options(favicon=False))

    candidate = context.candidates["104.16.1.1"]
    assert candidate.is_cdn is True
    assert probed == [], "a CDN address must not be probed"


def test_pipeline_validates_a_non_cdn_address(monkeypatch):
    context = make_context()
    monkeypatch.setattr(pipeline.probe, "baseline",
                        lambda *a, **k: make_response())
    monkeypatch.setattr(pipeline.discovery, "discover",
                        lambda *a, **k: {"203.0.113.9": ["ct: x"]})

    probed: list[str] = []
    monkeypatch.setattr(pipeline.validate, "validate",
                        lambda cand, ctx, **k: probed.append(cand.ip) or cand)

    pipeline.run(context, pipeline.Options(favicon=False))
    assert probed == ["203.0.113.9"]


def test_failed_baseline_becomes_a_warning_not_a_crash(monkeypatch):
    context = ScanContext(target="example.com")
    monkeypatch.setattr(pipeline.probe, "baseline",
                        lambda *a, **k: probe.Response(error="boom"))
    monkeypatch.setattr(pipeline.discovery, "discover", lambda *a, **k: {})

    pipeline.run(context, pipeline.Options(favicon=False))
    assert any("baseline" in warning for warning in context.warnings)


# â”€â”€ reporting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _scanned_context() -> ScanContext:
    context = make_context()
    good = context.candidate("203.0.113.9")
    good.add(Evidence(kind=EvidenceKind.TLS_EXACT_SAN, source="tls",
                      confidence=1.0))
    verdicts = __import__("origintrace.evidence", fromlist=["score_all"])
    context.verdicts = verdicts.score_all(list(context.candidates.values()))
    return context


def test_console_shows_the_verdict_and_ip():
    text = report.console(_scanned_context())
    assert "203.0.113.9" in text
    assert "ORIGIN" in text
    assert "confidence" in text


def test_console_says_so_when_nothing_was_found():
    context = make_context()
    text = report.console(context)
    assert "not identified" in text


def test_json_report_is_valid_and_complete():
    payload = json.loads(report.as_json(_scanned_context()))
    assert payload["target"] == "example.com"
    assert payload["verdicts"]
    assert payload["verdicts"][0]["origin_type"] == "EXPOSED_ORIGIN"


def test_markdown_report_has_a_verdict_section():
    text = report.as_markdown(_scanned_context())
    assert "# Origin report" in text
    assert "## Verdict" in text


def test_save_writes_both_artefacts(tmp_path):
    written = report.save(_scanned_context(), tmp_path)
    assert (tmp_path / "origintrace_example.com.json").is_file()
    assert (tmp_path / "origintrace_example.com.md").is_file()
    assert written["json"].endswith(".json")


# â”€â”€ CLI surface â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_cli_parser_exposes_the_documented_flags():
    from origintrace import cli
    parser = cli.build_parser()
    options = parser.parse_args(["example.com", "--json", "--hints",
                                 "--no-tls", "--probe-rules"])
    assert options.target == "example.com"
    assert options.json is True
    assert options.hints is True
    assert options.no_tls is True
    assert options.probe_rules is True


def test_cli_requires_a_target():
    from origintrace import cli
    parser = cli.build_parser()
    assert parser.parse_args([]).target is None

