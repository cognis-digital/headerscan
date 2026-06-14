"""Hardening tests — edge-cases, bad input, and error paths.

All network-touching paths (webhook) are tested without actually hitting
a server: we verify argument validation and early-exit behaviour only.
"""

from __future__ import annotations

import importlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headerscan import cli
from headerscan.core import (
    _check_hsts,
    grade_headers,
    parse_headers,
)


# ---------------------------------------------------------------------------
# core.parse_headers — type guard
# ---------------------------------------------------------------------------
class TestParseHeadersGuards(unittest.TestCase):
    def test_none_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_headers(None)  # type: ignore[arg-type]
        self.assertIn("str", str(ctx.exception))

    def test_integer_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_headers(42)  # type: ignore[arg-type]

    def test_empty_string_returns_empty(self):
        status, headers = parse_headers("")
        self.assertIsNone(status)
        self.assertEqual(headers, {})

    def test_whitespace_only_returns_empty(self):
        status, headers = parse_headers("   \n\t  \r\n  ")
        self.assertIsNone(status)
        self.assertEqual(headers, {})


# ---------------------------------------------------------------------------
# core.grade_headers — type + empty guard
# ---------------------------------------------------------------------------
class TestGradeHeadersGuards(unittest.TestCase):
    def test_none_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            grade_headers(None)  # type: ignore[arg-type]
        self.assertIn("str", str(ctx.exception))

    def test_empty_string_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            grade_headers("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_raises_value_error(self):
        with self.assertRaises(ValueError):
            grade_headers("   \n\t  ")

    def test_score_never_below_zero(self):
        # A response with every possible penalty should still score >= 0.
        all_leaky = (
            "HTTP/1.1 200 OK\n"
            "server: Apache/2.4\n"
            "x-powered-by: PHP/8\n"
            "x-aspnet-version: 4.0\n"
            "x-aspnetmvc-version: 5\n"
            "x-runtime: 0.250\n"
        )
        report = grade_headers(all_leaky)
        self.assertGreaterEqual(report.score, 0)
        self.assertLessEqual(report.score, 100)

    def test_score_never_above_100(self):
        # A perfectly hardened response scores at most 100.
        perfect = (
            "HTTP/2 200 OK\n"
            "strict-transport-security: max-age=63072000; includeSubDomains\n"
            "content-security-policy: default-src 'self'; frame-ancestors 'none'\n"
            "x-frame-options: DENY\n"
            "x-content-type-options: nosniff\n"
            "referrer-policy: no-referrer\n"
            "permissions-policy: geolocation=()\n"
        )
        report = grade_headers(perfect)
        self.assertLessEqual(report.score, 100)
        self.assertGreaterEqual(report.score, 0)


# ---------------------------------------------------------------------------
# core._check_hsts — capped max-age regex (no unbounded giant int)
# ---------------------------------------------------------------------------
class TestHstsEdgeCases(unittest.TestCase):
    def test_missing_max_age_treated_as_zero(self):
        finding = _check_hsts("preload; includeSubDomains", True)
        self.assertEqual(finding.status, "weak")
        self.assertIn("max-age=0", finding.message)

    def test_giant_digit_string_does_not_match(self):
        # A max-age value exceeding 15 digits is capped out by the regex
        # and falls back to 0 (treated as weak, not a crash).
        giant = "max-age=" + "9" * 30 + "; includeSubDomains"
        finding = _check_hsts(giant, True)
        # Must not raise; must produce a valid Finding.
        self.assertIn(finding.status, ("ok", "weak", "missing"))

    def test_valid_strong_hsts(self):
        finding = _check_hsts("max-age=63072000; includeSubDomains; preload", True)
        self.assertEqual(finding.status, "ok")


# ---------------------------------------------------------------------------
# CLI — exit codes and error messages for bad inputs
# ---------------------------------------------------------------------------
class TestCliHardening(unittest.TestCase):
    def setUp(self):
        self._real_stdout = sys.stdout
        self._real_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

    def tearDown(self):
        sys.stdout = self._real_stdout
        sys.stderr = self._real_stderr

    def test_missing_file_exits_2(self):
        rc = cli.main(["grade", "absolutely_does_not_exist_xyz.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", sys.stderr.getvalue())

    def test_empty_file_exits_2(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_empty.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("   \n  ")
        try:
            rc = cli.main(["grade", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 2)
        self.assertIn("empty", sys.stderr.getvalue().lower())

    def test_no_subcommand_exits_2(self):
        rc = cli.main([])
        self.assertEqual(rc, 2)

    def test_json_output_is_valid_on_bad_headers(self):
        # A response with only leak headers still produces parseable JSON.
        path = os.path.join(os.path.dirname(__file__), "_tmp_leaky.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 200 OK\nserver: nginx\n")
        try:
            rc = cli.main(["grade", path, "--format", "json"])
            out = sys.stdout.getvalue()
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)  # failed (grade < A)
        data = json.loads(out)
        self.assertIn("grade", data)
        self.assertIn("findings", data)


# ---------------------------------------------------------------------------
# mcp_server — importable without crash (scan/to_json were missing)
# ---------------------------------------------------------------------------
class TestMcpServerImport(unittest.TestCase):
    def test_module_imports_cleanly(self):
        """mcp_server must be importable without raising ImportError."""
        # Force a fresh import to catch top-level errors.
        if "headerscan.mcp_server" in sys.modules:
            del sys.modules["headerscan.mcp_server"]
        mod = importlib.import_module("headerscan.mcp_server")
        self.assertTrue(callable(getattr(mod, "serve", None)))


# ---------------------------------------------------------------------------
# webhook.py — argument validation (no network access)
# ---------------------------------------------------------------------------
class TestWebhookValidation(unittest.TestCase):
    """Test webhook.py argument validation logic without hitting a server."""

    def _run_webhook(self, argv, stdin_text=""):
        """Run webhook.main() with controlled stdin/stdout/stderr."""
        import integrations.webhook as wh

        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.argv = ["webhook.py"] + argv
        sys.stdin = io.StringIO(stdin_text)
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
        try:
            rc = wh.main()
        except SystemExit as exc:
            rc = int(exc.code) if exc.code is not None else 0
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        return rc

    def test_invalid_url_scheme_exits_2(self):
        rc = self._run_webhook(["--url", "ftp://example.com"], stdin_text='{"x":1}')
        self.assertEqual(rc, 2)

    def test_empty_stdin_exits_2(self):
        rc = self._run_webhook(["--url", "https://example.com"], stdin_text="   ")
        self.assertEqual(rc, 2)

    def test_malformed_header_flag_exits_2(self):
        rc = self._run_webhook(
            ["--url", "https://example.com", "--header", "BadHeaderNoColon"],
            stdin_text='{"x":1}',
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
