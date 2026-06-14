#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> grade resp.txt --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST headerscan JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https).")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header in 'Key: Value' format (repeatable).",
    )
    args = ap.parse_args()

    # Validate URL scheme before touching the network.
    url: str = args.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        print(
            f"webhook: --url must start with http:// or https://, got: {url!r}",
            file=sys.stderr,
        )
        return 2

    raw_text = sys.stdin.read()
    if not raw_text.strip():
        print("webhook: stdin is empty — nothing to POST", file=sys.stderr)
        return 2

    payload = raw_text.encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(
                f"webhook: --header value must be 'Key: Value', got: {h!r}",
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        name, value = k.strip(), v.strip()
        if not name:
            print(
                f"webhook: --header has empty key in: {h!r}",
                file=sys.stderr,
            )
            return 2
        req.add_header(name, value)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook error: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
