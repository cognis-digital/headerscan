"""HEADERSCAN — grade HTTP security headers A-F from a response dump.

Defensive/authorized-testing tool: analysis and triage only. It parses a
raw HTTP response (or header dump) you already captured and produces a
security-header report card in the spirit of securityheaders.com.

No network access, no attack capability — pure local analysis.
"""

from .core import (
    Finding,
    Report,
    grade_headers,
    parse_headers,
    score_to_grade,
)

TOOL_NAME = "headerscan"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Report",
    "grade_headers",
    "parse_headers",
    "score_to_grade",
    "TOOL_NAME",
    "TOOL_VERSION",
]
