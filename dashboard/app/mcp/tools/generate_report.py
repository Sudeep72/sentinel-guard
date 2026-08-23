"""``generate_report`` MCP tool."""

from __future__ import annotations

from sentinelguard_contracts import ReportFormat

from app.core.exceptions import NotFoundError
from app.mcp.tools._common import db_session
from app.services.report_service import generate_report as _generate_report


def generate_report(
    server_id: str, format: str = "executive", scan_id: str | None = None
) -> dict[str, object]:
    """Generate a report for a server's latest (or specified) scan.

    Args:
        server_id: The dashboard-issued server id.
        format: One of executive/technical/json/markdown.
        scan_id: Specific scan id, or the server's latest scan if omitted.
    """
    try:
        report_format = ReportFormat(format)
    except ValueError:
        valid = [f.value for f in ReportFormat]
        return {"available": False, "message": f"Unknown format {format!r}. Valid values: {valid}"}

    with db_session() as db:
        try:
            report = _generate_report(
                db, server_id=server_id, format=report_format, scan_id=scan_id
            )
        except NotFoundError as exc:
            return {"available": False, "message": str(exc)}

    return {"available": True, "report": report.model_dump(mode="json")}
