"""Smoke tests for HEADERSCAN. No network access."""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headerscan import (TOOL_NAME, TOOL_VERSION, grade_headers, parse_headers,
                        score_to_grade)
from headerscan import cli

STRONG = """HTTP/2 200 OK
content-type: text/html
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'self'; frame-ancestors 'none'
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: no-referrer
permissions-policy: geolocation=()
"""

WEAK = """HTTP/1.1 200 OK
server: nginx/1.21.6
x-powered-by: Express
content-security-policy: default-src *; script-src 'unsafe-inline'
strict-transport-security: max-age=100
"""


class TestParse(unittest.TestCase):
    def test_parse_status_and_headers(self):
        status, headers = parse_headers(STRONG)
        self.assertTrue(status.startswith("HTTP/2"))
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_body_is_ignored(self):
        raw = "HTTP/1.1 200 OK\nx-content-type-options: nosniff\n\nbody: nope\n"
        _, headers = parse_headers(raw)
        self.assertIn("x-content-type-options", headers)
        self.assertNotIn("body", headers)

    def test_bare_header_block(self):
        status, headers = parse_headers("X-Frame-Options: DENY\nReferrer-Policy: no-referrer\n")
        self.assertIsNone(status)
        self.assertEqual(headers["x-frame-options"], "DENY")


class TestGrading(unittest.TestCase):
    def test_strong_gets_top_grade(self):
        report = grade_headers(STRONG)
        self.assertIn(report.grade, ("A", "A+"))
        self.assertFalse(report.failed)
        self.assertEqual(report.missing, [])

    def test_weak_gets_low_grade_and_fails(self):
        report = grade_headers(WEAK)
        self.assertTrue(report.failed)
        self.assertLess(report.score, 75)
        statuses = {f.status for f in report.findings}
        self.assertIn("leak", statuses)
        self.assertIn("missing", statuses)

    def test_score_bounds(self):
        report = grade_headers("HTTP/1.1 200 OK\nserver: x\n")
        self.assertGreaterEqual(report.score, 0)
        self.assertLessEqual(report.score, 100)

    def test_score_to_grade_thresholds(self):
        self.assertEqual(score_to_grade(100), "A+")
        self.assertEqual(score_to_grade(90), "A")
        self.assertEqual(score_to_grade(70), "C")
        self.assertEqual(score_to_grade(10), "F")

    def test_to_dict_serializable(self):
        json.dumps(grade_headers(WEAK).to_dict())


class TestCli(unittest.TestCase):
    def setUp(self):
        self._stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        sys.stdout = self._stdout

    def test_json_format_and_exit_code(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_weak.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(WEAK)
        try:
            rc = cli.main(["grade", path, "--format", "json"])
            out = sys.stdout.getvalue()
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)
        self.assertIn("grade", json.loads(out))

    def test_strong_exits_zero(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_strong.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(STRONG)
        try:
            rc = cli.main(["grade", path, "--format", "json"])
        finally:
            os.remove(path)
        self.assertEqual(rc, 0)

    def test_missing_file_exits_two(self):
        self.assertEqual(cli.main(["grade", "does_not_exist_12345.txt"]), 2)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "headerscan")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
