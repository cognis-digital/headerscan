"""HEADERSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from headerscan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-headerscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-headerscan[mcp]'")
        return 1
    app = FastMCP("headerscan")

    @app.tool()
    def headerscan_scan(target: str) -> str:
        """Grade HTTP security headers (CSP/HSTS/XFO) A-F from a response dump. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
