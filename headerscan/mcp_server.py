"""HEADERSCAN MCP server — exposes grade_headers() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import sys
from headerscan.core import grade_headers


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-headerscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-headerscan[mcp]'",
            file=sys.stderr,
        )
        return 1

    app = FastMCP("headerscan")

    @app.tool()
    def headerscan_scan(raw_response: str) -> str:
        """Grade HTTP security headers (CSP/HSTS/XFO) A-F from a response dump.

        Pass the raw HTTP response text (headers section). Returns JSON findings.
        """
        if not isinstance(raw_response, str) or not raw_response.strip():
            return json.dumps({"error": "raw_response must be a non-empty string"})
        try:
            report = grade_headers(raw_response)
            return json.dumps(report.to_dict())
        except Exception as exc:  # pragma: no cover
            return json.dumps({"error": str(exc)})

    app.run()
    return 0
