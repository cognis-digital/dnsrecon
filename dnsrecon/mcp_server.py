"""DNSRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from dnsrecon.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dnsrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-dnsrecon[mcp]'")
        return 1
    app = FastMCP("dnsrecon")

    @app.tool()
    def dnsrecon_scan(target: str) -> str:
        """Aggregate DNS recon (records, zone hints, takeover candidates). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
