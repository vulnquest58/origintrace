"""Rule engine: identify the stack, then optionally check known weak endpoints.

Two separate jobs live here and they have different risk profiles:

* **Detection** parses a rule's ``detection`` block against the baseline
  response. It is read-only in effect — it inspects headers, cookies and body
  markers that the target already sent us. Always on.
* **Probing** sends the rule's ``safe_probes`` paths. Those requests are real
  traffic and some of them (an SSRF parameter, an auth-bypass header) can trip a
  WAF or look like exploitation. It is therefore **opt-in** via
  ``--probe-rules`` and never runs by default.

Being explicit about that split is not politeness: a scanner that quietly sends
``/.env.local`` to a production origin gets hunters banned from programs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from origintrace.models import Finding

logger = logging.getLogger("origintrace.rules")

#: Rules live *inside* the package so an installed copy still finds them.
#: Keeping them at the repository root meant a wheel could not ship them, and
#: `--rules` then reported "no rules loaded" on a clean install.
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass
class ProbeSpec:
    """One endpoint a rule wants to try."""

    path: str
    method: str = "GET"
    risk: str = "MEDIUM"
    description: str = ""
    tags: List[str] = field(default_factory=list)
    expected_status: List[int] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass
class Rule:
    """A parsed YAML rule."""

    name: str
    category: str = "unknown"
    version: str = "0"
    headers: List[Dict[str, object]] = field(default_factory=list)
    body_patterns: List[Dict[str, object]] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    probes: List[ProbeSpec] = field(default_factory=list)
    source_path: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "probes": len(self.probes),
            "source": self.source_path,
        }


def _compile(pattern: str):
    try:
        return re.compile(pattern, re.I)
    except re.error:
        return None


def load_rule(path: Path) -> Optional[Rule]:
    """Parse one YAML file. A malformed rule is skipped, not fatal."""
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is required to load rules")
        return None

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - bad YAML must not stop the scan
        logger.warning("rule %s unreadable: %s", path.name, exc)
        return None

    if not isinstance(data, dict) or not data.get("name"):
        return None

    detection = data.get("detection") or {}
    rule = Rule(
        name=str(data["name"]),
        category=str(data.get("category", "unknown")),
        version=str(data.get("version", "0")),
        cookies=[str(c) for c in (detection.get("cookies") or [])],
        source_path=str(path.name),
    )

    for entry in detection.get("headers") or []:
        if isinstance(entry, dict) and entry.get("name"):
            rule.headers.append({
                "name": str(entry["name"]).lower(),
                "pattern": _compile(str(entry.get("pattern", ""))),
                "confidence": float(entry.get("confidence", 60)) / 100.0,
            })

    for entry in detection.get("body_patterns") or []:
        if isinstance(entry, dict) and entry.get("pattern"):
            rule.body_patterns.append({
                "pattern": _compile(str(entry["pattern"])),
                "confidence": float(entry.get("confidence", 60)) / 100.0,
            })

    # Both key spellings appear in the ported library.
    for entry in (data.get("probes") or data.get("safe_probes") or []):
        if not isinstance(entry, dict) or not entry.get("path"):
            continue
        rule.probes.append(ProbeSpec(
            path=str(entry["path"]),
            method=str(entry.get("method", "GET")).upper(),
            risk=str(entry.get("risk", "MEDIUM")).upper(),
            description=str(entry.get("description", "")).strip(),
            tags=[str(t) for t in (entry.get("tags") or [])],
            expected_status=[int(s) for s in (entry.get("expected_status") or [])
                             if str(s).isdigit()],
            headers={str(k): str(v) for k, v in (entry.get("headers") or {}).items()},
            body=str(entry.get("body", "")),
        ))

    return rule


def load_rules(directory: Optional[Path] = None) -> List[Rule]:
    """Load every ``*.yaml`` under ``directory``, recursively."""
    root = Path(directory or DEFAULT_RULES_DIR)
    if not root.is_dir():
        logger.warning("rules directory missing: %s", root)
        return []
    rules = [load_rule(path) for path in sorted(root.rglob("*.yaml"))]
    return [rule for rule in rules if rule is not None]


# ══════════════════════════════════════════════════════════════════════════════
#  Detection
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class Detection:
    """A matched rule and the confidence the signals justify."""

    rule: str
    confidence: float
    signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule": self.rule,
            "confidence": round(self.confidence, 2),
            "signals": list(self.signals),
        }


def detect(rules: Iterable[Rule], headers: Dict[str, str], body: str) -> List[Detection]:
    """Match the rules that fire on a section of a response.

    Confidence uses the same saturating combination as the evidence engine: three
    corroborating markers should not read as 250%.
    """
    lowered_headers = {str(k).lower(): str(v).lower()
                       for k, v in (headers or {}).items()}
    body_lower = (body or "")[:65536].lower()
    cookie_blob = lowered_headers.get("set-cookie", "")

    results: List[Detection] = []
    for rule in rules:
        signals: List[str] = []
        weights: List[float] = []

        for spec in rule.headers:
            value = lowered_headers.get(str(spec["name"]))
            pattern = spec["pattern"]
            if value and pattern and pattern.search(value):
                weights.append(float(spec["confidence"]))
                signals.append(f"header {spec['name']}={value[:60]}")

        for spec in rule.body_patterns:
            pattern = spec["pattern"]
            if body_lower and pattern and pattern.search(body_lower):
                weights.append(float(spec["confidence"]))
                signals.append(f"body {pattern.pattern[:40]}")

        for cookie in rule.cookies:
            if cookie.lower() in cookie_blob:
                weights.append(0.5)
                signals.append(f"cookie {cookie}")

        if not weights:
            continue

        product = 1.0
        for weight in weights:
            product *= (1.0 - min(1.0, weight))
        results.append(Detection(rule=rule.name,
                                 confidence=1.0 - product,
                                 signals=signals))

    results.sort(key=lambda item: item.confidence, reverse=True)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  Probing (opt-in)
# ══════════════════════════════════════════════════════════════════════════════


def probe_rules(rule: Rule, base_url: str, timeout: float = 6.0,
                max_paths: int = 8) -> List[Finding]:
    """Send the rule's probe paths and record anything that answered.

    A hit is only reported as ``confirmed`` when the status matched what the rule
    expected **and** the soft-404 guard saw a different response for a random
    path. Without that guard every "200 OK" from a SPA router is a finding.
    """
    import httpx

    findings: List[Finding] = []
    base = base_url.rstrip("/")

    soft = _soft_404(base, timeout)

    for spec in rule.probes[:max_paths]:
        url = f"{base}{spec.path}"
        try:
            with httpx.Client(timeout=timeout, verify=False, trust_env=False,
                              follow_redirects=False) as client:
                response = client.request(
                    spec.method, url,
                    headers={"User-Agent": "origintrace/1.0", **spec.headers},
                    content=spec.body.encode() if spec.body else None,
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("probe failed %s: %s", url, exc)
            continue

        expected = spec.expected_status or [200]
        matched = response.status_code in expected
        body = response.text[:4096]
        confirmed = matched and not _resembles(soft, body)

        if not matched and not confirmed:
            continue

        findings.append(Finding(
            rule=rule.name,
            path=spec.path,
            method=spec.method,
            risk=spec.risk,
            description=spec.description,
            tags=list(spec.tags),
            status_code=response.status_code,
            evidence=body[:200],
            confirmed=confirmed,
        ))

    return findings


def _soft_404(base: str, timeout: float) -> str:
    """Body of a deliberately non-existent path, used to suppress router noise."""
    import uuid
    import httpx
    try:
        with httpx.Client(timeout=timeout, verify=False, trust_env=False) as client:
            response = client.get(f"{base}/origintrace-{uuid.uuid4().hex[:8]}")
            return response.text[:4096]
    except Exception:  # noqa: BLE001
        return ""


def _resembles(soft: str, body: str) -> bool:
    """True when ``body`` is the same shape as the soft-404 page."""
    if not soft or not body:
        return False
    import difflib
    return difflib.SequenceMatcher(None, soft, body[:4096]).ratio() > 0.85
