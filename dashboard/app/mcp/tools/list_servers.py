"""``list_servers`` MCP tool."""

from __future__ import annotations

from app.mcp.tools._common import db_session
from app.services.server_service import list_servers as _list_servers


def list_servers() -> dict[str, object]:
    """List every server registered in the SentinelGuard fleet."""
    with db_session() as db:
        servers = _list_servers(db)
    return {"servers": [s.model_dump(mode="json") for s in servers]}
