"""``health`` MCP tool."""

from __future__ import annotations

from app.api.v1.health import check_health
from app.mcp.tools._common import db_session


def health() -> dict[str, object]:
    """Check SentinelGuard Dashboard health, including database connectivity."""
    with db_session() as db:
        result = check_health(db)
    return result.model_dump()
