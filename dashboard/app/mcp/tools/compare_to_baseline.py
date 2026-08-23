"""``compare_to_baseline`` MCP tool."""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.mcp.tools._common import db_session
from app.services.baseline_service import compare_to_baseline as _compare_to_baseline


def compare_to_baseline(server_id: str, category: str | None = None) -> dict[str, object]:
    """Compare a server's current state against its distro's security baseline.

    Args:
        server_id: The dashboard-issued server id.
        category: Restrict to one Guardian category, or all if omitted.
    """
    with db_session() as db:
        try:
            response = _compare_to_baseline(db, server_id=server_id, category=category)
        except NotFoundError as exc:
            return {"available": False, "message": str(exc)}
    return response.model_dump(mode="json")
