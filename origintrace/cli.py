"""Command line interface.

Three verbs, no more:

    origintrace example.com              # find the origin
    origintrace example.com --json       # machine-readable
    origintrace --explain 203.0.113.9 -d example.com

The scope warning is printed to stderr once per run and is not suppressible.
This tool is used against production systems; making that reminder optional
would be the wrong default.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from origintrace import intel, pipeline, report, rules
from origintrace.models import ScanContext

BANNER = "origintrace 1.0.0 — evidence-first origin intelligence"

SCOPE_NOTICE = (
    "Only use this against systems you are authorised to test. "
    "Every request is a plain GET; nothing is exploited."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="origintrace",
        description=BANNER,
        epilog=SCOPE_NOTICE,
    )
    parser.add_argument("target", nargs="?",
                        help="domain to investigate (e.g. example.com)")
    parser.add_argument("-d", "--domain", default="",
                        help="target domain when the positional is an IP")

    mode = parser.add_argument_group("output")
    mode.add_argument("--json", action="store_true",
                      help="emit JSON instead of the console view")
    mode.add_argument("--markdown", action="store_true",
                      help="emit a Markdown report")
    mode.add_argument("--save", metavar="DIR",
                      help="write both JSON and Markdown into DIR")
    mode.add_argument("-v", "--verbose", action="store_true",
                      help="show every candidate and note")
    mode.add_argument("--explain", metavar="IP",
                      help="explain the score of one IP from a previous run")

    behaviour = parser.add_argument_group("behaviour")
    behaviour.add_argument("--sub", action="append", default=[],
                           metavar="NAME", help="extra subdomain hint (repeatable)")
    behaviour.add_argument("--hints", action="store_true",
                           help="also try the built-in subdomain hints")
    behaviour.add_argument("--no-tls", action="store_true",
                           help="skip certificate identity checks")
    behaviour.add_argument("--no-tlsfp", action="store_true",
                           help="skip TLS stack fingerprint comparison")
    behaviour.add_argument("--jarm", action="store_true",
                           help="run the active JARM-style TLS fingerprint "
                                "(ten crafted ClientHellos per host)")
    behaviour.add_argument("--no-favicon", action="store_true",
                           help="skip favicon comparison")
    behaviour.add_argument("--extended", action="store_true",
                           help="also run the advanced passive sources "
                                "(SPF, DMARC, robots, sitemap, CSP, wayback, "
                                "reverse-IP, certificate SAN expansion)")
    behaviour.add_argument("--all", action="store_true", dest="all_techniques",
                           help="enable every technique: --extended and --hints")
    behaviour.add_argument("--progress", action="store_true",
                           help="stream each source's result as it completes")
    behaviour.add_argument("--timeout", type=float, default=8.0,
                           help="per-request timeout in seconds (default 8)")
    behaviour.add_argument("--max", type=int, default=40, dest="max_candidates",
                           help="cap on candidates to validate (default 40)")

    extra = parser.add_argument_group("extras")
    extra.add_argument("--rules", action="store_true",
                       help="identify the stack from the rule library")
    extra.add_argument("--probe-rules", action="store_true",
                       help="REQUEST the rules' probe paths (sends traffic; off "
                            "by default)")
    extra.add_argument("--list-rules", action="store_true",
                       help="print the loaded rule library and exit")
    extra.add_argument("--datasets", action="store_true",
                       help="print dataset counts and exit")
    extra.add_argument("--version", action="version", version=BANNER)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.datasets:
        info = intel.dataset_info()
        for name, count in info.items():
            print(f"{name:<16} {count}")
        return 0

    if args.list_rules:
        loaded = rules.load_rules()
        print(f"{len(loaded)} rule(s)")
        for rule in sorted(loaded, key=lambda r: (r.category, r.name)):
            print(f"  {rule.category:<14} {rule.name:<24} "
                  f"{len(rule.probes)} probe(s)")
        return 0

    target = (args.domain or args.target or "").strip()
    if not target:
        parser.print_help()
        return 2

    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.rstrip("/").lower()

    print(SCOPE_NOTICE, file=sys.stderr)

    context = ScanContext(target=target)
    options = pipeline.Options(
        tls=not args.no_tls,
        tlsfp=not args.no_tlsfp,
        jarm=args.jarm or args.all_techniques,
        favicon=not args.no_favicon,
        extended=args.extended or args.all_techniques,
        subdomains=list(args.sub or []),
        use_hints=args.hints or args.all_techniques,
        timeout=args.timeout,
        max_candidates=args.max_candidates,
        progress=_progress_printer() if args.progress else None,
    )
    pipeline.run(context, options)

    if args.rules or args.probe_rules:
        _apply_rules(context, allow_probes=args.probe_rules)

    if args.explain:
        print(pipeline.explain_candidate(context, args.explain))
        return 0

    if args.json:
        print(report.as_json(context))
    elif args.markdown:
        print(report.as_markdown(context))
    else:
        print(report.console(context, verbose=args.verbose))

    if args.save:
        written = report.save(context, Path(args.save))
        print(f"saved: {written['json']}")
        print(f"saved: {written['markdown']}")

    best = context.best
    if best and best.origin_type.value in ("EXPOSED_ORIGIN", "PROTECTED_ORIGIN"):
        return 0
    return 1 if not context.candidates else 1


def _progress_printer():
    """Stream one line per completed step to stderr.

    stderr keeps stdout clean for ``--json``, so a pipeline can consume the
    report while a human still sees progress.
    """
    def reporter(stage: str, message: str) -> None:
        print(f"  [{stage:<12}] {message}", file=sys.stderr, flush=True)
    return reporter


def _apply_rules(context: ScanContext, allow_probes: bool) -> None:
    """Identify the stack from the baseline, optionally probing endpoints."""
    loaded = rules.load_rules()
    if not loaded:
        context.warn("no rules loaded")
        return

    base = context.target if "://" in context.target else f"https://{context.target}"
    from origintrace import probe

    response = probe.baseline(base, timeout=8.0)
    detections = rules.detect(loaded, response.headers, response.body)
    context.stats["stack_detected"] = len(detections)

    for detection in detections[:6]:
        context.warn(
            f"stack: {detection.rule} "
            f"({detection.confidence * 100:.0f}% — {', '.join(detection.signals[:2])})"
        )

    if not allow_probes:
        if detections:
            context.warn(
                "probe rules not sent (use --probe-rules to request known paths)"
            )
        return

    by_name = {rule.name: rule for rule in loaded}
    for detection in detections[:4]:
        rule = by_name.get(detection.rule)
        if rule is None:
            continue
        for finding in rules.probe_rules(rule, base):
            context.add_finding(finding)


if __name__ == "__main__":
    raise SystemExit(main())
