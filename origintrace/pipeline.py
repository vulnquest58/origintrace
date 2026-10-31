"""Pipeline: discovery -> classification -> validation -> scoring.

The order is not arbitrary:

1. **Baseline first.** Without the public page there is nothing to compare
   against, and comparing against nothing is how tools report a parking page as
   an origin.
2. **Classify before validating.** A Cloudflare edge node never needs a vhost
   probe; skipping it saves most of the runtime on a CDN-protected target.
3. **Validate, then score.** Scoring reads evidence, so it must run last.

Each stage records what it skipped and why, and every skip surfaces in the
report. A silent skip looks identical to a negative result, which is the single
easiest way to mislead an operator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from origintrace import discover as discovery
from origintrace import evidence as scoring
from origintrace import intel, probe, validate
from origintrace.models import (
    Candidate,
    Evidence,
    EvidenceKind,
    OriginType,
    ScanContext,
    digest,
)

logger = logging.getLogger("origintrace.pipeline")


@dataclass
class Options:
    """Knobs exposed by the CLI, grouped so the pipeline signature stays small."""

    #: Validate the target's own resolved IPs too (they normally sit on the CDN
    #: and are classified away early, but a misconfigured target can expose one).
    validate_current: bool = True

    #: Skip TLS identity checks — useful behind a TLS-terminating proxy.
    tls: bool = True

    #: Compare TLS stack fingerprints. One extra handshake per candidate.
    tlsfp: bool = True

    #: Run the JARM-style active fingerprint (ten crafted ClientHellos per host).
    #: Off by default: it is roughly twenty extra connections per host, which is
    #: acceptable for a handful of candidates and rude for forty.
    jarm: bool = False

    #: Compare favicons. Cheap and strong, but does one extra request per IP.
    favicon: bool = True

    #: Run the advanced passive sources (SPF, robots, CSP, wayback, reverse-IP).
    extended: bool = False

    #: Extra subdomain hints to resolve.
    subdomains: List[str] = field(default_factory=list)

    #: Network timeout for HTTP probes.
    timeout: float = 8.0

    #: Hard cap on candidates, so a wildcard-DNS target cannot melt the run.
    max_candidates: int = 40

    #: Use the built-in hint wordlist in addition to ``subdomains``.
    use_hints: bool = False

    #: Called as ``progress(stage, message)`` so the CLI can stream results.
    progress: Optional[object] = None


def _emit(options: Options, stage: str, message: str) -> None:
    """Send a live progress line if a callback was supplied."""
    callback = options.progress
    if callable(callback):
        try:
            callback(stage, message)
        except Exception:  # noqa: BLE001 - progress must never break a scan
            pass


def _baseline(context: ScanContext, options: Options) -> None:
    """Fetch the public page and store what later stages compare against."""
    response = probe.baseline(context.target, timeout=options.timeout)
    context.baseline_status = response.status
    context.baseline_title = response.title
    context.baseline_headers = dict(response.headers)
    context.baseline_body_hash = response.body_hash

    # The raw body is kept on the context (not in ``stats``), because scoring
    # needs it and dropping it would silently degrade every similarity check.
    context.stats["_baseline_body_len"] = len(response.body)
    setattr(context, "_baseline_body", response.body)
    context.stats["baseline_hfp"] = int(
        response.header_fingerprint(), 16
    ) if _is_hex(response.header_fingerprint()) else 0

    if not response.ok:
        context.warn(
            f"baseline fetch failed ({response.error or response.status}); "
            "content comparison will be limited to header/behaviour signals"
        )
        return

    # Favicon is part of the baseline because it is the strongest cheap signal.
    if options.favicon:
        icon = _fetch_favicon(context.target, options.timeout)
        if icon:
            context.baseline_favicon = icon

    context.bump("baseline_ok")


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except (TypeError, ValueError):
        return False


def _fetch_favicon(target: str, timeout: float) -> str:
    import hashlib
    import httpx
    base = target if "://" in target else f"https://{target}"
    try:
        with httpx.Client(timeout=timeout, verify=False, trust_env=False) as client:
            response = client.get(f"{base.rstrip('/')}/favicon.ico")
            if response.status_code == 200 and response.content:
                return hashlib.sha256(response.content).hexdigest()[:16]
    except Exception:  # noqa: BLE001
        pass
    return ""


def _classify(candidates: Iterable[Candidate], context: ScanContext) -> None:
    """Attach CDN/WAF/ASN facts so downstream stages can skip edge nodes."""
    for candidate in candidates:
        owner = intel.cdn_owner(candidate.ip)
        candidate.is_cdn = owner is not None
        candidate.cdn_name = owner or ""
        if owner:
            candidate.add(Evidence(
                kind=EvidenceKind.HOSTED_ON_CDN,
                source="intel",
                confidence=1.0,
                details={"provider": owner},
            ))
            context.bump("edge_nodes")
        else:
            context.bump("non_cdn")


def run(context: ScanContext, options: Optional[Options] = None) -> ScanContext:
    """Execute the full pipeline for ``context.target``."""
    options = options or Options()
    started = time.monotonic()

    # ── 1. baseline ─────────────────────────────────────────────────────────
    _emit(options, "baseline", f"fetching https://{context.target}/")
    _baseline(context, options)
    _emit(options, "baseline",
          f"{context.baseline_status} · {context.baseline_title[:50] or '(no title)'}")

    # ── 2. discovery ────────────────────────────────────────────────────────
    subdomains = list(options.subdomains)
    if options.use_hints:
        subdomains.extend(discovery.COMMON_HINTS)

    from origintrace import discover as _discovery

    sources = list(_discovery.DEFAULT_SOURCES)
    if options.extended:
        # Advanced sources are opt-in: every one of them makes an outbound
        # request to a third party, which should be a deliberate choice.
        sources.extend(_discovery.extended_sources(context.baseline_headers))
        _emit(options, "discovery",
              f"{len(sources)} sources ({len(sources) - len(_discovery.DEFAULT_SOURCES)} advanced)")

    def _on_source(name: str, count: int, error: str) -> None:
        note = f"error: {error}" if error else f"{count} new address(es)"
        _emit(options, f"source:{name}", note)

    found = _discovery.discover(
        context.target, sources=sources, subdomains=subdomains,
        progress=_on_source if options.progress else None,
    )
    for ip, trail in found.items():
        candidate = context.track(ip, "discovery", "; ".join(trail[:3]))
        joined = " ".join(trail)
        if "ct:" in joined:
            candidate.add(Evidence(kind=EvidenceKind.CERT_TRANSPARENCY,
                                   source="ct", confidence=0.8,
                                   details={"trail": trail[:3]}))
        if "mx:" in joined:
            candidate.add(Evidence(kind=EvidenceKind.PASSIVE_DNS_HISTORY,
                                   source="mx", confidence=0.7,
                                   details={"trail": trail[:3]}))
        if "spf:" in joined:
            candidate.add(Evidence(kind=EvidenceKind.SPF_OR_MX_LEAK,
                                   source="spf", confidence=0.8,
                                   details={"trail": trail[:3]}))

    context.bump("discovered", len(found))
    _emit(options, "discovery", f"{len(found)} candidate address(es)")

    # ── 3. classification ───────────────────────────────────────────────────
    candidates = list(context.candidates.values())[: options.max_candidates]
    _classify(candidates, context)
    _emit(options, "classify",
          f"{context.stats.get('edge_nodes', 0)} behind a CDN, "
          f"{context.stats.get('non_cdn', 0)} direct")

    # ── 4. validation ───────────────────────────────────────────────────────
    baseline_fp = None
    if options.tlsfp:
        baseline_fp = _baseline_fingerprint(context, options)

    baseline_jarm = None
    if options.jarm:
        baseline_jarm = _jarm_baseline(context, options)

    for candidate in candidates:
        if candidate.is_cdn and not options.validate_current:
            continue
        if candidate.is_cdn:
            # Still scored, but not probed: an edge node answers for thousands of
            # sites, so a match would be meaningless and the request pointless.
            context.bump("skipped_edge")
            _emit(options, "validate", f"{candidate.ip}  skipped (CDN edge)")
            continue

        before = len(candidate.evidence)
        validate.validate(candidate, context, with_tls=options.tls,
                          with_favicon=options.favicon)

        if options.tlsfp:
            _fingerprint_candidate(candidate, context, baseline_fp, options)

        if options.jarm:
            _jarm_candidate(candidate, context, baseline_jarm, options)

        context.bump("validated")
        _emit(options, "validate",
              f"{candidate.ip}  {len(candidate.evidence) - before} signal(s)")

    # ── 5. scoring ──────────────────────────────────────────────────────────
    context.verdicts = scoring.score_all(list(context.candidates.values()))
    context.bump("elapsed_ms", int((time.monotonic() - started) * 1000))

    best = context.best
    if best and best.origin_type in (OriginType.EXPOSED_ORIGIN,
                                     OriginType.PROTECTED_ORIGIN):
        context.bump("origins_found")

    return context


def _baseline_fingerprint(context: ScanContext, options: Options):
    """Fingerprint the public endpoint so candidates can be compared to it."""
    from origintrace import probe, tlsfp

    for ip in probe.resolve(context.target, "A")[:1]:
        result = tlsfp.fingerprint(ip, context.target, timeout=options.timeout)
        if result.ok:
            context.stats["baseline_tlsfp"] = result.digest  # type: ignore[assignment]
            _emit(options, "tlsfp", f"baseline {result.version}/{result.cipher}")
            return result
    return None


def _fingerprint_candidate(candidate: Candidate, context: ScanContext,
                           baseline, options: Options) -> None:
    """Add a TLS-stack match when the candidate's stack equals the baseline's."""
    from origintrace import tlsfp

    if baseline is None or not baseline.ok:
        return

    result = tlsfp.fingerprint(candidate.ip, context.target,
                              timeout=options.timeout)
    if not tlsfp.compare(baseline, result):
        return

    candidate.add(Evidence(
        kind=EvidenceKind.TLS_JARM_MATCH,
        source="tlsfp",
        confidence=1.0,
        details={"digest": result.digest, "version": result.version,
                 "cipher": result.cipher},
    ))


def _jarm_baseline(context: ScanContext, options: Options):
    """Fingerprint the public endpoint with the active JARM probes."""
    from origintrace import jarm

    result = jarm.fingerprint(context.target, timeout=options.timeout)
    if result.ok:
        context.stats["baseline_jarm"] = 1  # type: ignore[assignment]
        _emit(options, "jarm", f"baseline {result.fingerprint[:24]}…")
        return result
    _emit(options, "jarm", f"baseline failed: {result.error}")
    return None


def _jarm_candidate(candidate: Candidate, context: ScanContext, baseline,
                    options: Options) -> None:
    """Attach a JARM match when the candidate's active fingerprint is identical.

    This is the signal that survives a shared hosting provider's identical web
    server: two machines behind the same reverse-proxy version answer the ten
    probes byte-for-byte the same way, whatever their content.
    """
    from origintrace import jarm

    if baseline is None or not baseline.ok:
        return

    result = jarm.fingerprint(candidate.ip, timeout=options.timeout)
    if not jarm.compare(baseline.fingerprint, result.fingerprint):
        return

    candidate.add(Evidence(
        kind=EvidenceKind.TLS_JARM_MATCH,
        source="jarm",
        confidence=0.85,
        details={"fingerprint": result.fingerprint},
    ))


def explain_candidate(context: ScanContext, ip: str) -> str:
    """Render the score breakdown for one IP (used by ``--explain``)."""
    candidate = context.candidates.get(ip)
    if candidate is None:
        return f"{ip}: not seen in this scan"
    return scoring.explain(candidate)
