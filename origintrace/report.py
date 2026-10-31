"""Report rendering: console, JSON and Markdown.

The console view is the product. A hunter should be able to read the verdict and
the reason for it without scrolling, so the layout puts the decision on the left
and the evidence underneath, and never prints more than a handful of candidate
rows — the rest are reachable with ``--verbose``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

from origintrace.models import OriginType, ScanContext, Verdict

#: Order matters: the first type found wins the headline.
_HEADLINE_ORDER = [
    OriginType.EXPOSED_ORIGIN,
    OriginType.PROTECTED_ORIGIN,
    OriginType.SHADOW_ORIGIN,
    OriginType.HOSTING_ORIGIN,
    OriginType.UNCERTAIN,
]


def _badge(verdict: Verdict) -> str:
    mapping = {
        OriginType.EXPOSED_ORIGIN: "ORIGIN",
        OriginType.PROTECTED_ORIGIN: "PROTECTED",
        OriginType.SHADOW_ORIGIN: "SHADOW",
        OriginType.HOSTING_ORIGIN: "HOSTING",
        OriginType.EDGE_NODE: "CDN",
        OriginType.REJECTED: "rejected",
        OriginType.UNCERTAIN: "uncertain",
    }
    return mapping.get(verdict.origin_type, "?")


def console(context: ScanContext, verbose: bool = False,
            limit: int = 8) -> str:
    """Render the human view."""
    lines: List[str] = []
    best = context.best

    lines.append("")
    lines.append(f"  target    {context.target}")
    if context.baseline_title:
        lines.append(f"  baseline  {context.baseline_status} · "
                     f"{context.baseline_title[:60]}")
    elif context.baseline_status:
        lines.append(f"  baseline  {context.baseline_status}")

    discovered = context.stats.get("discovered", 0)
    edges = context.stats.get("edge_nodes", 0)
    lines.append(f"  found     {discovered} address(es), {edges} behind a CDN")

    if discovered and not edges:
        # No CDN in front means there is nothing to bypass. Saying "ORIGIN" here
        # would imply a bypass that did not happen, which is exactly the kind of
        # overclaim this tool exists to avoid.
        lines.append("            no CDN detected — these are the serving "
                     "addresses, not a bypass")

    if best and best.origin_type in _HEADLINE_ORDER:
        lines.append("")
        lines.append(f"  ORIGIN  {best.candidate.ip}   "
                     f"confidence {best.confidence:.0f}/100   "
                     f"[{_badge(best)}]")
        if best.candidate.as_org:
            lines.append(f"          {best.candidate.as_org}")
        for reason in _top_reasons(best):
            lines.append(f"          {reason}")
    else:
        lines.append("")
        lines.append("  ORIGIN  not identified")
        if not discovered:
            lines.append("          no candidate addresses were discovered")
        else:
            lines.append("          candidates found but none matched strongly "
                         "enough to call an origin")

    rows = [v for v in context.verdicts
            if v.origin_type is not OriginType.REJECTED]
    if rows:
        lines.append("")
        lines.append("  candidates")
        for verdict in rows[:limit]:
            lines.append(
                f"    {verdict.candidate.ip:<16} {_badge(verdict):<10} "
                f"{verdict.confidence:5.0f}   "
                f"{_summary(verdict.candidate)}"
            )
        if len(rows) > limit and not verbose:
            lines.append(f"    … {len(rows) - limit} more (--verbose)")

    if context.findings:
        lines.append("")
        lines.append("  findings")
        for finding in context.findings[:limit]:
            mark = "!" if finding.confirmed else "?"
            lines.append(f"    {mark} [{finding.risk:<8}] {finding.path} "
                         f"({finding.status_code}) {finding.rule}")

    if context.warnings:
        lines.append("")
        for warning in context.warnings:
            lines.append(f"  note: {warning}")

    lines.append("")
    return "\n".join(lines)


def _top_reasons(verdict: Verdict, limit: int = 4) -> List[str]:
    """Only the strongest few reasons: a wall of evidence is not a reason."""
    positives = [r for r in verdict.reasons if r.startswith("+")]
    negatives = [r for r in verdict.reasons if r.startswith("-")]
    return (positives[:limit] + negatives[:2])


def _summary(candidate) -> str:
    bits = []
    kinds = [k for k in candidate.kinds()]
    for kind in kinds[:3]:
        bits.append(kind.value)
    if candidate.cdn_name:
        bits.insert(0, f"cdn:{candidate.cdn_name}")
    return " · ".join(bits)


def as_json(context: ScanContext) -> str:
    return json.dumps(context.to_dict(), indent=2, ensure_ascii=False)


def as_markdown(context: ScanContext) -> str:
    """A report suitable for pasting into a ticket or a write-up."""
    best = context.best
    lines = [
        f"# Origin report — {context.target}",
        "",
        f"- Started: `{context.started}`",
        f"- Candidates: {context.stats.get('discovered', 0)}",
        f"- Behind CDN: {context.stats.get('edge_nodes', 0)}",
        "",
    ]

    if best and best.origin_type in _HEADLINE_ORDER:
        lines += [
            "## Verdict",
            "",
            f"**{best.origin_type.value}** at `{best.candidate.ip}` "
            f"(confidence {best.confidence:.0f}/100)",
            "",
            "| Signal | Contribution |",
            "| --- | --- |",
        ]
        for reason in best.reasons:
            text = reason.strip()
            if text.startswith(("+", "-")):
                mark = text[0]
                name = text[1:].strip()
                lines.append(f"| {mark} {name} | |")
    else:
        lines += ["## Verdict", "", "No origin identified.", ""]

    lines += ["", "## Candidates", "",
              "| IP | Type | Confidence | CDN |", "| --- | --- | --- | --- |"]
    for verdict in context.verdicts:
        if verdict.origin_type is OriginType.REJECTED:
            continue
        lines.append(
            f"| `{verdict.candidate.ip}` | {verdict.origin_type.value} | "
            f"{verdict.confidence:.0f} | {verdict.candidate.cdn_name or '—'} |"
        )

    if context.findings:
        lines += ["", "## Findings", ""]
        for finding in context.findings:
            confidence = "confirmed" if finding.confirmed else "unconfirmed"
            lines.append(
                f"- **{finding.risk}** `{finding.path}` — {finding.rule} "
                f"({confidence}, {finding.status_code})"
            )

    if context.warnings:
        lines += ["", "## Notes", ""]
        lines += [f"- {warning}" for warning in context.warnings]

    return "\n".join(lines) + "\n"


def save(context: ScanContext, directory: Path, stem: Optional[str] = None) -> dict:
    """Write both machine and human artefacts; returns the paths written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stem = stem or f"origintrace_{context.target.replace('/', '_')}"
    json_path = directory / f"{stem}.json"
    md_path = directory / f"{stem}.md"
    json_path.write_text(as_json(context), encoding="utf-8")
    md_path.write_text(as_markdown(context), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
