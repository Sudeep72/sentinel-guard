"""MCP server bootstrap.

Registers all eight required tools against a single FastMCP instance,
each backed by the exact same ``app/services/`` functions the REST API
uses (see ``app/mcp/tools/``). Run via the ``sentinelguard-mcp`` console
script, which uses the stdio transport — the standard integration
pattern for Claude Desktop / Claude Code, which launch MCP servers as
trusted local subprocesses.

**Auth model:** unlike the REST API (a shared multi-client HTTP surface
that authenticates every single request independently), this MCP
server authenticates once at process startup via
``SENTINELGUARD_MCP_TOKEN`` — a JWT obtained the same way a human user
would via ``POST /api/v1/auth/token``, validated with the same
``decode_access_token`` the REST layer uses. This matches the trust
model of a locally-launched subprocess. A remote-hosted MCP deployment
(SSE/HTTP transport with per-request auth) is out of scope for v1; this
module is the seam where that would be added later without touching
any tool implementation.
"""

from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP

from app.auth.jwt import InvalidTokenError, decode_access_token
from app.mcp.tools.compare_to_baseline import compare_to_baseline
from app.mcp.tools.explain_finding import explain_finding
from app.mcp.tools.generate_report import generate_report
from app.mcp.tools.get_security_score import get_security_score
from app.mcp.tools.health import health
from app.mcp.tools.list_findings import list_findings
from app.mcp.tools.list_servers import list_servers
from app.mcp.tools.scan_server import scan_server

mcp_app = FastMCP("SentinelGuard")

# Registered explicitly (rather than via decorators on the tool modules)
# so each tool function stays a plain, directly-testable Python callable
# with zero MCP-framework coupling — see tests/test_mcp/.
mcp_app.tool(name="health")(health)
mcp_app.tool(name="scan_server")(scan_server)
mcp_app.tool(name="get_security_score")(get_security_score)
mcp_app.tool(name="list_findings")(list_findings)
mcp_app.tool(name="explain_finding")(explain_finding)
mcp_app.tool(name="compare_to_baseline")(compare_to_baseline)
mcp_app.tool(name="generate_report")(generate_report)
mcp_app.tool(name="list_servers")(list_servers)


def authenticate_session(token: str | None) -> None:
    """Validate the MCP session token once at startup.

    Raises:
        SystemExit: If the token is missing or invalid — the server
            refuses to start rather than serving unauthenticated.
    """
    if not token:
        print(
            "SENTINELGUARD_MCP_TOKEN is required to start the MCP server. "
            "Obtain one via POST /api/v1/auth/token.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        decode_access_token(token)
    except InvalidTokenError:
        print("SENTINELGUARD_MCP_TOKEN is invalid or expired.", file=sys.stderr)
        raise SystemExit(1) from None


def run() -> None:
    """Entrypoint for the ``sentinelguard-mcp`` console script (stdio transport)."""
    authenticate_session(os.environ.get("SENTINELGUARD_MCP_TOKEN"))
    mcp_app.run()


if __name__ == "__main__":
    run()
