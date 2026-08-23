"""``scan_server`` MCP tool.

Design note: v1 has no reverse channel to command an agent to scan on
demand — Background Workers / a Job Scheduler are explicitly deferred
to v2 (see ROADMAP.md). Agents push scans on their own schedule; this
tool honestly reports the most recent known scan rather than pretending
to trigger a live one, which is the most an on-demand "scan_server"
call can do within the approved v1 architecture.
"""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.mcp.tools._common import db_session
from app.services.scan_service import get_latest_scan
from app.services.server_service import get_server


def scan_server(server_id: str) -> dict[str, object]:
    """Get the latest scan status for a server.

    Args:
        server_id: The dashboard-issued server id.
    """
    with db_session() as db:
        try:
            server = get_server(db, server_id)
        except NotFoundError as exc:
            return {"available": False, "message": str(exc)}

        latest = get_latest_scan(db, server_id)
        if latest is None:
            return {
                "available": False,
                "server_id": server_id,
                "message": (
                    "No scans submitted yet for this server. Agents push scans on "
                    "their own schedule; on-demand remote triggering is not available "
                    "in v1 (see ROADMAP.md — Background Workers / Job Scheduler are v2)."
                ),
            }

        return {
            "available": True,
            "server": server.model_dump(mode="json"),
            "scan": {
                "id": latest.id,
                "started_at": latest.started_at.isoformat(),
                "completed_at": latest.completed_at.isoformat(),
                "status": latest.status,
            },
        }
