"""Report generation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sentinelguard_contracts import Report, ReportFormat
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.models.user import User
from app.services.report_service import generate_report

router = APIRouter(prefix="/servers", tags=["reports"])


@router.get("/{server_id}/report", response_model=Report)
def get_report(
    server_id: str,
    format: ReportFormat = Query(default=ReportFormat.EXECUTIVE),
    scan_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Report:
    """Generate a report for a server's latest (or specified) scan."""
    try:
        return generate_report(db, server_id=server_id, format=format, scan_id=scan_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
