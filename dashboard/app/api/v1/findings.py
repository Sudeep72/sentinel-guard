"""Finding query endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.models.user import User
from app.schemas.findings import FindingRecord
from app.services.finding_service import explain_finding, list_findings

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingRecord])
def get_findings(
    server_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[FindingRecord]:
    """List findings, optionally filtered by server, severity, category, or status."""
    return list_findings(
        db,
        server_id=server_id,
        severity=severity,
        category=category,
        status=status_filter,
    )


@router.get("/{finding_id}", response_model=FindingRecord)
def get_finding_detail(
    finding_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)
) -> FindingRecord:
    """Fetch full detail for a single finding."""
    try:
        return explain_finding(db, finding_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
