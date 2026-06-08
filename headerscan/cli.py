"""Command-line interface for HEADERSCAN.

Usage:
    headerscan grade response.txt            # grade a saved response dump
    headerscan grade -                       # read from stdin
    headerscan grade resp.txt --format json  # machine-readable output
    headerscan --version

Exit codes:
    0  grade A/A+ (no significant findings)
    1  findings present (grade B or lower)
    2  usage / read error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Report, grade_headers

GRADE_LABEL = {
    "A+": "EXCELLENT", "A": "GOOD", "B": "FAIR",
    "C": "WEAK", "D": "POOR", "F": "FAILING",
}


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _render_table(report: Report) -> str:
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append(f" HEADERSCAN report card -- Grade {report.grade} "
                 f"({GRADE_LABEL.get(report.grade, '')}, score {report.score}/100)")
    if report.status_line:
        lines.append(f" Response: {report.status_line}")
    lines.append("=" * 60)
    lines.append(f"{'STATUS':<8} {'SEV':<9} {'-PTS':<5} HEADER")
    lines.append("-" * 60)
    icon = {"ok": "OK", "weak": "WEAK", "missing": "MISS", "leak": "LEAK"}
    for f in report.findings:
        lines.append(f"{icon.get(f.status, f.status):<8} {f.severity:<9} "
                     f"{('-' + str(f.penalty)) if f.penalty else '0':<5} {f.header}")
        lines.append(f"         {f.message}")
    lines.append("-" * 60)
    if report.missing:
        lines.append("Missing: " + ", ".join(report.missing))
    lines.append("=" * 60)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Grade HTTP security headers (CSP/HSTS/XFO ...) A-F "
                    "from a captured response dump. Defensive analysis only.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    grade_p = sub.add_parser(
        "grade", help="Grade a saved HTTP response / header dump.")
    grade_p.add_argument(
        "source",
        help="Path to a file containing the HTTP response/headers, or '-' for stdin.")
    grade_p.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "grade":
        parser.print_help(sys.stderr)
        return 2

    try:
        raw = _read_source(args.source)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read {args.source!r}: {exc}", file=sys.stderr)
        return 2

    if not raw.strip():
        print(f"{TOOL_NAME}: input is empty", file=sys.stderr)
        return 2

    report = grade_headers(raw)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
