"""Command-line interface.

Subcommands:
  parse    — parse logs and emit normalized events as JSONL
  analyze  — parse + run detection rules, print alerts, optionally save to JSONL
  rules    — list loaded detection rules
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .parsers import ALL_PARSERS
from .detectors import DetectionEngine, RuleSet
from .storage import open_sink, write_jsonl
from . import alerter
from . import __version__

DEFAULT_RULES = Path(__file__).parent / "rules" / "default.yaml"


def _open_input(path: str):
    if path == "-":
        return sys.stdin
    return open(path, "r", encoding="utf-8", errors="replace")


def cmd_parse(args: argparse.Namespace) -> int:
    parser_cls = ALL_PARSERS[args.format]
    parser = parser_cls()

    parsed = 0
    with _open_input(args.input) as src, open_sink(args.output) as sink:
        for event in parser.parse_stream(src, strict=args.strict):
            write_jsonl(event.to_dict(), sink)
            parsed += 1

    skipped = getattr(parser, "skipped", 0)
    print(f"# parsed={parsed} skipped={skipped}", file=sys.stderr)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    parser_cls = ALL_PARSERS[args.format]
    parser = parser_cls()
    ruleset = RuleSet.from_yaml(args.rules)
    engine = DetectionEngine(ruleset)

    parsed = 0
    alerts_count = 0

    events_sink_cm = open_sink(args.events_output) if args.events_output else None
    alerts_sink_cm = open_sink(args.alerts_output) if args.alerts_output else None

    events_sink = events_sink_cm.__enter__() if events_sink_cm else None
    alerts_sink = alerts_sink_cm.__enter__() if alerts_sink_cm else None

    try:
        with _open_input(args.input) as src:
            for event in parser.parse_stream(src, strict=args.strict):
                parsed += 1
                if events_sink:
                    write_jsonl(event.to_dict(), events_sink)
                for alert in engine.process(event):
                    alerts_count += 1
                    if not args.quiet:
                        alerter.print_alert(alert)
                    if alerts_sink:
                        write_jsonl(alert.to_dict(), alerts_sink)
    finally:
        if events_sink_cm:
            events_sink_cm.__exit__(None, None, None)
        if alerts_sink_cm:
            alerts_sink_cm.__exit__(None, None, None)

    skipped = getattr(parser, "skipped", 0)
    alerter.print_summary(
        total_lines=parsed + skipped,
        parsed=parsed,
        skipped=skipped,
        alerts=alerts_count,
    )
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    ruleset = RuleSet.from_yaml(args.rules)
    for r in ruleset.rules:
        thr = ""
        if r.threshold:
            thr = f" [threshold: {r.threshold.count}/{r.threshold.window_seconds}s by {','.join(r.threshold.group_by)}]"
        print(f"{r.id:30s} {r.severity:8s} {r.name}{thr}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-ingestor",
        description="Modular log parser and rule-based detector for SIEM pipelines.",
    )
    p.add_argument("--version", action="version", version=f"log-ingestor {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    common_input = argparse.ArgumentParser(add_help=False)
    common_input.add_argument("input", help="Path to log file, or '-' for stdin")
    common_input.add_argument(
        "-f", "--format", choices=list(ALL_PARSERS.keys()), default="auto",
        help="Input format (default: auto-detect)",
    )
    common_input.add_argument("--strict", action="store_true",
                              help="Fail on first unparseable line instead of skipping")

    p_parse = sub.add_parser("parse", parents=[common_input],
                             help="Parse logs and emit normalized events as JSONL")
    p_parse.add_argument("-o", "--output", default="-", help="Output path or '-' for stdout (JSONL)")
    p_parse.set_defaults(func=cmd_parse)

    p_analyze = sub.add_parser("analyze", parents=[common_input],
                               help="Parse + run detection rules")
    p_analyze.add_argument("-r", "--rules", default=str(DEFAULT_RULES),
                           help=f"Path to rules YAML (default: {DEFAULT_RULES})")
    p_analyze.add_argument("--events-output", default=None,
                           help="Optional path to write parsed events as JSONL")
    p_analyze.add_argument("--alerts-output", default=None,
                           help="Optional path to write alerts as JSONL")
    p_analyze.add_argument("-q", "--quiet", action="store_true",
                           help="Suppress per-alert console output (still writes to file)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_rules = sub.add_parser("rules", help="List loaded detection rules")
    p_rules.add_argument("-r", "--rules", default=str(DEFAULT_RULES))
    p_rules.set_defaults(func=cmd_rules)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
