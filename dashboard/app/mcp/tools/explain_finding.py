"""``explain_finding`` MCP tool."""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.mcp.tools._common import db_session
from app.services.finding_service import explain_finding as _explain_finding


def explain_finding(finding_id: str) -> dict[str, object]:
    """Get full detail for one finding: why it matters, attack scenario, recommendation.

    Args:
        finding_id: The dashboard-issued finding id (from ``list_findings``).
    """
    with db_session() as db:
        try:
            finding = _explain_finding(db, finding_id)
        except NotFoundError as exc:
            return {"available": False, "message": str(exc)}
    return {"available": True, "finding": finding.model_dump(mode="json")}
