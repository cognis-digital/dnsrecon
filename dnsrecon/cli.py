"""Command-line interface for DNSRECON."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import Severity, analyze_records, load_records, summarize


def _render_table(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"DNSRECON {TOOL_VERSION}  records={report['records_analyzed']}  "
                 f"findings={report['findings_total']}")
    types = report.get("record_types", {})
    if types:
        lines.append("types: " + ", ".join(f"{k}={v}" for k, v in types.items()))
    sev = report.get("findings_by_severity", {})
    if sev:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        parts = [f"{s}={sev[s]}" for s in order if s in sev]
        lines.append("severity: " + ", ".join(parts))
    lines.append("")
    findings = report.get("findings", [])
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for f in findings:
        head = f"[{f['severity'].upper():8}] {f['rule']}  {f['name']}"
        if f.get("record_type"):
            head += f"  ({f['record_type']})"
        lines.append(head)
        lines.append(f"    {f['detail']}")
        if f.get("value"):
            lines.append(f"    value: {f['value']}")
        if f.get("recommendation"):
            lines.append(f"    fix: {f['recommendation']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Defensive DNS recon aggregator (offline analysis only).",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze",
                             help="Analyze a DNS record file for attack-surface findings.")
    analyze.add_argument("input", help="Path to JSON or text DNS record file.")
    analyze.add_argument("--format", choices=["table", "json"], default="table",
                         help="Output format (default: table).")
    analyze.add_argument("--min-severity",
                         choices=["info", "low", "medium", "high", "critical"],
                         default="info",
                         help="Only report findings at or above this severity.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "analyze":
        try:
            records = load_records(args.input)
        except FileNotFoundError:
            print(f"error: input file not found: {args.input}", file=sys.stderr)
            return 2
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"error: failed to parse records: {exc}", file=sys.stderr)
            return 2

        findings = analyze_records(records)
        threshold = Severity.rank(args.min_severity)
        findings = [f for f in findings if Severity.rank(f.severity) >= threshold]
        report = summarize(records, findings)

        if args.format == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(_render_table(report))

        # Non-zero exit when findings are present (CI gate friendly).
        return 1 if findings else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
