"""``list_findings`` MCP tool."""

from __future__ import annotations

from app.mcp.tools._common import db_session
from app.services.finding_service import list_findings as _list_findings


def list_findings(
    server_id: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> dict[str, object]:
    """List findings, optionally filtered by server, severity, category, or status.

    Args:
        server_id: Restrict to one server, or all servers if omitted.
        severity: One of critical/high/medium/low/info.
        category: One of the nine Guardian categories.
        status: One of open/resolved/accepted_risk/false_positive.
    """
    with db_session() as db:
        findings = _list_findings(
            db, server_id=server_id, severity=severity, category=category, status=status
        )
    return {"findings": [f.model_dump(mode="json") for f in findings]}
