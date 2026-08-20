"""CLI entry point for ThreatLens Desktop."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatlens.exporters import as_html, as_json, as_text, write_report
from threatlens.service import AnalysisService


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatlens", description="Local-first defensive static analysis")
    actions = parser.add_subparsers(dest="command", required=True)
    for name, target_help in (("scan-file", "Local file to inspect without execution"), ("scan-url", "Public http(s) URL to inspect passively")):
        command = actions.add_parser(name)
        command.add_argument("target", help=target_help)
        command.add_argument("--format", choices=("text", "json", "html"), default="text")
        command.add_argument("--output", help="Write the report to a local path")
    history = actions.add_parser("history", help="Search the local analysis history")
    history.add_argument("query", nargs="?", default="")
    history.add_argument("--limit", type=int, default=25)
    actions.add_parser("gui", help="Launch the optional Tkinter desktop interface")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "gui":
        from threatlens.gui import launch

        launch()
        return 0
    service = AnalysisService()
    if args.command == "history":
        rows = service.history.search(args.query, args.limit)
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    try:
        report = service.analyze_file(args.target) if args.command == "scan-file" else service.analyze_url(args.target)
    except (ValueError, OSError) as exc:
        print(f"ThreatLens: {exc}", file=sys.stderr)
        return 2
    rendered = {"text": as_text, "json": as_json, "html": as_html}[args.format](report)
    if args.output:
        write_report(report, Path(args.output), args.format)
    else:
        print(rendered, end="")
    return 1 if report.risk_score >= 40 else 0


if __name__ == "__main__":
    raise SystemExit(main())

