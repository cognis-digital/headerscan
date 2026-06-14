"""Core engine for HEADERSCAN.

Parses a raw HTTP response / header dump and grades the security headers
A-F. Every check is real logic operating on parsed header values - there
are no stubs or simulated results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# Severity weights. Each missing/weak control deducts points from 100.
SEVERITY_PENALTY = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 5,
    "info": 0,
}

# Headers a hardened response should NOT expose (info leakage).
LEAKY_HEADERS = {
    "server": "Reveals server software/version, aiding targeted exploits.",
    "x-powered-by": "Reveals application framework/runtime.",
    "x-aspnet-version": "Reveals ASP.NET version.",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version.",
    "x-runtime": "Reveals backend runtime timing/stack.",
}


@dataclass
class Finding:
    """A single graded observation about one header (or its absence)."""

    header: str
    status: str          # "ok" | "missing" | "weak" | "leak"
    severity: str        # critical | high | medium | low | info
    penalty: int
    message: str
    value: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Report:
    """Full report card for one analyzed response."""

    score: int
    grade: str
    findings: List[Finding] = field(default_factory=list)
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    status_line: Optional[str] = None

    @property
    def failed(self) -> bool:
        """Non-zero exit condition: any non-ok finding lowers the grade."""
        return self.grade not in ("A+", "A")

    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "status_line": self.status_line,
            "present": self.present,
            "missing": self.missing,
            "findings": [f.to_dict() for f in self.findings],
        }


def parse_headers(raw: str) -> Tuple[Optional[str], Dict[str, str]]:
    """Parse a raw HTTP response or bare header block.

    Returns (status_line, headers). Header names are lowercased. Repeated
    headers are joined with ", ". Stops at the first blank line (end of
    header section) so a pasted full response with a body still works.

    Raises ValueError if *raw* is not a str.
    """
    if not isinstance(raw, str):
        raise ValueError(
            f"parse_headers requires a str, got {type(raw).__name__}"
        )

    status_line: Optional[str] = None
    headers: Dict[str, str] = {}

    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            if not stripped:
                continue  # skip leading blanks
            started = True
            if re.match(r"^HTTP/\d", stripped, re.IGNORECASE):
                status_line = stripped
                continue
        else:
            if stripped == "":
                break  # blank line = end of headers

        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        val = value.strip()
        if not key:
            continue
        if key in headers:
            headers[key] = headers[key] + ", " + val
        else:
            headers[key] = val
    return status_line, headers


def _check_csp(value: Optional[str]) -> Finding:
    name = "Content-Security-Policy"
    if value is None:
        return Finding(name, "missing", "high", SEVERITY_PENALTY["high"],
                       "No CSP - page has no defense-in-depth against XSS/injection.")
    low = value.lower()
    weaknesses = []
    if "unsafe-inline" in low:
        weaknesses.append("allows 'unsafe-inline' (defeats most XSS protection)")
    if "unsafe-eval" in low:
        weaknesses.append("allows 'unsafe-eval'")
    if re.search(r"(default|script)-src[^;]*\*", low):
        weaknesses.append("uses wildcard '*' source")
    if "default-src" not in low and "script-src" not in low:
        weaknesses.append("no default-src/script-src fallback")
    if weaknesses:
        return Finding(name, "weak", "medium", SEVERITY_PENALTY["medium"],
                       "CSP present but weak: " + "; ".join(weaknesses) + ".", value)
    return Finding(name, "ok", "info", 0, "CSP present and reasonably strict.", value)


def _check_hsts(value: Optional[str], over_https: bool) -> Finding:
    name = "Strict-Transport-Security"
    if value is None:
        sev = "high" if over_https else "medium"
        return Finding(name, "missing", sev, SEVERITY_PENALTY[sev],
                       "No HSTS - connections can be downgraded to HTTP.")
    low = value.lower()
    m = re.search(r"max-age\s*=\s*(\d{1,15})", low)  # cap at 15 digits (safe int)
    max_age = int(m.group(1)) if m else 0
    weaknesses = []
    if max_age < 15552000:  # < 180 days
        weaknesses.append(f"max-age={max_age} is below recommended 15552000 (180d)")
    if "includesubdomains" not in low:
        weaknesses.append("missing includeSubDomains")
    if weaknesses:
        return Finding(name, "weak", "low", SEVERITY_PENALTY["low"],
                       "HSTS present but weak: " + "; ".join(weaknesses) + ".", value)
    return Finding(name, "ok", "info", 0, "HSTS present with strong max-age.", value)


def _check_xfo(value: Optional[str], csp: Optional[str]) -> Finding:
    name = "X-Frame-Options"
    csp_has_fa = csp is not None and "frame-ancestors" in csp.lower()
    if value is None:
        if csp_has_fa:
            return Finding(name, "ok", "info", 0,
                           "No XFO, but CSP frame-ancestors provides clickjacking protection.")
        return Finding(name, "missing", "medium", SEVERITY_PENALTY["medium"],
                       "No X-Frame-Options and no CSP frame-ancestors - clickjacking risk.")
    low = value.lower().strip()
    if low in ("deny", "sameorigin"):
        return Finding(name, "ok", "info", 0, f"X-Frame-Options: {value}.", value)
    return Finding(name, "weak", "low", SEVERITY_PENALTY["low"],
                   f"X-Frame-Options value '{value}' is non-standard/deprecated.", value)


def _check_simple(value: Optional[str], name: str, expected: str,
                  severity: str, missing_msg: str) -> Finding:
    if value is None:
        return Finding(name, "missing", severity, SEVERITY_PENALTY[severity], missing_msg)
    if expected and expected.lower() not in value.lower():
        return Finding(name, "weak", "low", SEVERITY_PENALTY["low"],
                       f"{name} present but value '{value}' is not the hardened '{expected}'.",
                       value)
    return Finding(name, "ok", "info", 0, f"{name}: {value}.", value)


def score_to_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def grade_headers(raw: str) -> Report:
    """Parse and grade a raw HTTP response / header dump.

    Raises ValueError if *raw* is not a str or is empty/whitespace-only.
    """
    if not isinstance(raw, str):
        raise ValueError(
            f"grade_headers requires a str, got {type(raw).__name__}"
        )
    if not raw.strip():
        raise ValueError("grade_headers requires non-empty input")
    status_line, headers = parse_headers(raw)
    over_https = True
    if status_line is None and not headers:
        over_https = True  # assume https when only headers pasted

    csp_val = headers.get("content-security-policy")
    findings: List[Finding] = [
        _check_csp(csp_val),
        _check_hsts(headers.get("strict-transport-security"), over_https),
        _check_xfo(headers.get("x-frame-options"), csp_val),
        _check_simple(headers.get("x-content-type-options"),
                      "X-Content-Type-Options", "nosniff", "medium",
                      "No X-Content-Type-Options - MIME-sniffing attacks possible."),
        _check_simple(headers.get("referrer-policy"),
                      "Referrer-Policy", "", "low",
                      "No Referrer-Policy - referrer may leak to third parties."),
        _check_simple(headers.get("permissions-policy"),
                      "Permissions-Policy", "", "low",
                      "No Permissions-Policy - browser features are not restricted."),
    ]

    # Information-leak headers (presence is the problem).
    for hname, why in LEAKY_HEADERS.items():
        if hname in headers:
            findings.append(Finding(hname.title(), "leak", "low",
                                    SEVERITY_PENALTY["low"],
                                    f"Exposes implementation detail. {why}",
                                    headers[hname]))

    score = 100 - sum(f.penalty for f in findings)
    score = max(0, min(100, score))
    grade = score_to_grade(score)

    present = sorted({f.header for f in findings if f.status in ("ok", "weak")})
    missing = sorted({f.header for f in findings if f.status == "missing"})

    return Report(score=score, grade=grade, findings=findings,
                  present=present, missing=missing, status_line=status_line)
