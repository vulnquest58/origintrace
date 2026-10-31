"""Core data model.

Everything in origintrace is built around one idea: a claim about an IP must be
backed by named evidence. :class:`Evidence` is the unit, :class:`Candidate` is
the subject, and :class:`Verdict` is the conclusion the pipeline is allowed to
draw once every module has reported.

Design decisions worth knowing before editing this file:

* **Weights are positive only.** A module that observes something supporting an
  origin claim adds weight; it never subtracts. Contradicting observations are
  modelled as their own evidence with a ``negative`` flag (see
  :class:`EvidenceKind`) so the report can show *why* a candidate was rejected
  instead of silently dropping it.
* **Confidence is per-observation, weight is per-kind.** A single TLS match at
  confidence 0.9 and three behavioural matches are not the same thing; keeping
  the two numbers separate is what makes the final score auditable.
* **Nothing here performs I/O.** That keeps the model trivially testable and
  lets every module be exercised offline.

Author: vulnquest58
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
#  Enumerations
# ══════════════════════════════════════════════════════════════════════════════


class OriginType(str, Enum):
    """What a candidate IP turned out to be.

    The distinction between ``PROTECTED_ORIGIN`` and ``EXPOSED_ORIGIN`` matters:
    an origin that still sits behind a WAF is worth reporting but is not the
    "CDN bypassed" finding most hunters are after, and confusing the two is how
    tools end up with false positives.
    """

    EXPOSED_ORIGIN = "EXPOSED_ORIGIN"
    PROTECTED_ORIGIN = "PROTECTED_ORIGIN"
    SHADOW_ORIGIN = "SHADOW_ORIGIN"
    EDGE_NODE = "EDGE_NODE"
    HOSTING_ORIGIN = "HOSTING_ORIGIN"
    REJECTED = "REJECTED"
    UNCERTAIN = "UNCERTAIN"


class EvidenceKind(str, Enum):
    """Named observations.

    The string value is used verbatim in JSON output and in rule files, so it is
    part of the public contract. Adding a kind is safe; renaming one is not.
    """

    # Identity: the candidate demonstrably serves the target.
    TLS_SAN_MATCH = "tls_san_match"
    TLS_EXACT_SAN = "tls_exact_san"
    TLS_WILDCARD_SAN = "tls_wildcard_san"
    TLS_CERT_REUSED = "tls_cert_reused"
    TLS_JARM_MATCH = "tls_jarm_match"

    # Behaviour: the candidate responds like the real site to a bare vhost.
    VHOST_IDENTICAL = "vhost_identical"
    CONTENT_SIMILAR = "content_similar"
    TITLE_MATCH = "title_match"
    FAVICON_MATCH = "favicon_match"
    HEADER_FINGERPRINT_MATCH = "header_fingerprint_match"
    ETAG_MATCH = "etag_match"
    REDIRECT_CHAIN_MATCH = "redirect_chain_match"

    # Provenance: where the candidate came from.
    PASSIVE_DNS_HISTORY = "passive_dns_history"
    CERT_TRANSPARENCY = "cert_transparency"
    SPF_OR_MX_LEAK = "spf_or_mx_leak"
    SUBDOMAIN_UNIQUE_IP = "subdomain_unique_ip"
    OPERATOR_SUPPLIED = "operator_supplied"

    # Infrastructure classification (informational, never proves an origin).
    HOSTED_ON_CDN = "hosted_on_cdn"
    BEHIND_WAF = "behind_waf"
    SHARED_HOSTING = "shared_hosting"
    DEFAULT_PAGE = "default_page"

    # Disqualifying observations.
    CATCH_ALL_VHOST = "catch_all_vhost"
    GENERIC_PARKING_PAGE = "generic_parking_page"
    CHALLENGE_PAGE = "challenge_page"
    UNREACHABLE = "unreachable"


#: Kinds that *reduce* trust. Kept explicit so the scorer cannot be surprised by
#: a module inventing a new negative signal.
NEGATIVE_KINDS = frozenset(
    {
        EvidenceKind.CATCH_ALL_VHOST,
        EvidenceKind.GENERIC_PARKING_PAGE,
        EvidenceKind.CHALLENGE_PAGE,
        EvidenceKind.UNREACHABLE,
        EvidenceKind.SHARED_HOSTING,
    }
)


@dataclass(frozen=True)
class Evidence:
    """One observation about a candidate.

    ``details`` is free-form and ends up in the JSON report; put the concrete
    values there (the SAN that matched, the similarity score, the JARM hash) so
    a reader can reproduce the conclusion without rerunning the tool.
    """

    kind: EvidenceKind
    source: str
    weight: float = 0.0
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # ``kind`` is typed as the enum but callers (and JSON round-trips) hand
        # over plain strings. Coercing here means a typo in a module produces a
        # clear ValueError instead of an AttributeError deep inside the scorer.
        if not isinstance(self.kind, EvidenceKind):
            object.__setattr__(self, "kind", EvidenceKind(self.kind))

        clamp = lambda v: max(0.0, min(1.0, float(v)))  # noqa: E731
        object.__setattr__(self, "weight", clamp(self.weight))
        object.__setattr__(self, "confidence", clamp(self.confidence))

    @property
    def negative(self) -> bool:
        return self.kind in NEGATIVE_KINDS

    @property
    def score(self) -> float:
        """Signed contribution to a candidate's score.

        A positive observation contributes ``weight * confidence``; a negative
        one contributes the same magnitude, subtracted. Keeping the sign here
        (rather than in the scorer) means every consumer agrees on the meaning.
        """
        magnitude = self.weight * self.confidence
        return -magnitude if self.negative else magnitude

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "weight": round(self.weight, 4),
            "confidence": round(self.confidence, 4),
            "score": round(self.score, 4),
            "negative": self.negative,
            "details": _jsonable(self.details),
        }


@dataclass
class Candidate:
    """An IP under investigation, with everything observed about it."""

    ip: str
    evidence: List[Evidence] = field(default_factory=list)

    #: Filled in by the intel layer. ``None`` means "not classified yet" and is
    #: different from ``False`` ("classified and clean").
    is_cdn: Optional[bool] = None
    cdn_name: str = ""
    is_waf: Optional[bool] = None
    waf_name: str = ""
    asn: str = ""
    as_org: str = ""

    #: Human-readable trail of how this IP was found (source: detail).
    discovered_by: List[str] = field(default_factory=list)

    #: The HTML title observed when probing the vhost, kept for the report.
    title: str = ""
    status_code: int = 0

    def add(self, evidence: Evidence) -> "Candidate":
        """Attach an observation. Returning ``self`` keeps module code linear."""
        self.evidence.append(evidence)
        return self

    def has(self, kind: EvidenceKind) -> bool:
        return any(item.kind is kind for item in self.evidence)

    def kinds(self) -> List[EvidenceKind]:
        seen: List[EvidenceKind] = []
        for item in self.evidence:
            if item.kind not in seen:
                seen.append(item.kind)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "is_cdn": self.is_cdn,
            "cdn_name": self.cdn_name,
            "is_waf": self.is_waf,
            "waf_name": self.waf_name,
            "asn": self.asn,
            "as_org": self.as_org,
            "title": self.title,
            "status_code": self.status_code,
            "discovered_by": list(self.discovered_by),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class Verdict:
    """The scored conclusion about one candidate."""

    candidate: Candidate
    score: float = 0.0
    origin_type: OriginType = OriginType.UNCERTAIN
    reasons: List[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """Map the raw score onto a 0-100 confidence.

        The scale is intentionally conservative: a candidate needs more than a
        single strong signal to be called an origin, because one module can be
        wrong and two independent ones rarely agree by accident.
        """
        return max(0.0, min(100.0, self.score * 100.0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.candidate.ip,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 1),
            "origin_type": self.origin_type.value,
            "reasons": list(self.reasons),
            "candidate": self.candidate.to_dict(),
        }


@dataclass
class Finding:
    """A rule-based observation produced by the probe engine."""

    rule: str
    path: str
    method: str
    risk: str
    description: str
    tags: List[str] = field(default_factory=list)

    #: Evidence that the hit is real rather than a soft-404.
    status_code: int = 0
    evidence: str = ""
    confirmed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "path": self.path,
            "method": self.method,
            "risk": self.risk,
            "description": self.description,
            "tags": list(self.tags),
            "status_code": self.status_code,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
        }


@dataclass
class ScanContext:
    """State carried through the pipeline for one target."""

    target: str
    started: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    #: The hostname actually used for vhost probing (the target as given).
    vhost: str = ""

    #: Baseline fetched from the public target, used for comparison.
    baseline_title: str = ""
    baseline_status: int = 0
    baseline_headers: Dict[str, str] = field(default_factory=dict)
    baseline_favicon: str = ""
    baseline_body_hash: str = ""

    candidates: Dict[str, Candidate] = field(default_factory=dict)
    verdicts: List[Verdict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    #: Non-fatal problems, surfaced in the report so a silent failure is visible.
    warnings: List[str] = field(default_factory=list)

    #: Free-form counters for the summary boxes.
    stats: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.vhost:
            self.vhost = self.target

    # ── candidates ───────────────────────────────────────────────────────────

    def candidate(self, ip: str) -> Candidate:
        """Get or create the candidate for ``ip``."""
        if ip not in self.candidates:
            self.candidates[ip] = Candidate(ip=ip)
        return self.candidates[ip]

    def track(self, ip: str, source: str, detail: str = "") -> Candidate:
        """Record that ``ip`` was discovered, and by whom."""
        found = self.candidate(ip)
        label = f"{source}: {detail}" if detail else source
        if label not in found.discovered_by:
            found.discovered_by.append(label)
        return found

    # ── findings ─────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def bump(self, key: str, amount: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + amount

    # ── summary helpers ──────────────────────────────────────────────────────

    @property
    def best(self) -> Optional[Verdict]:
        """The highest-scoring verdict, or ``None`` when nothing was found."""
        if not self.verdicts:
            return None
        return max(self.verdicts, key=lambda item: item.score)

    def by_type(self, origin_type: OriginType) -> List[Verdict]:
        return [v for v in self.verdicts if v.origin_type is origin_type]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vhost": self.vhost,
            "started": self.started,
            "finished": datetime.now(timezone.utc).isoformat(),
            "baseline": {
                "title": self.baseline_title,
                "status": self.baseline_status,
                "favicon": self.baseline_favicon,
            },
            "stats": dict(self.stats),
            "warnings": list(self.warnings),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "findings": [f.to_dict() for f in self.findings],
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════


def _jsonable(value: Any) -> Any:
    """Best-effort conversion so a stray bytes/Path cannot break the report."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")[:400]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return str(value)


def digest(value: str) -> str:
    """Short stable hash used for fingerprints (favicons, bodies, headers)."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
