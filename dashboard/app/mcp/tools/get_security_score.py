"""``get_security_score`` MCP tool."""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.mcp.tools._common import db_session
from app.services.score_service import get_security_score as _get_security_score


def get_security_score(server_id: str, scan_id: str | None = None) -> dict[str, object]:
    """Get the security score for a server's latest (or specified) scan.

    Args:
        server_id: The dashboard-issued server id.
        scan_id: Specific scan id, or the server's latest scan if omitted.
    """
    with db_session() as db:
        try:
            response = _get_security_score(db, server_id=server_id, scan_id=scan_id)
        except NotFoundError as exc:
            return {"available": False, "message": str(exc)}
    return response.model_dump(mode="json")
