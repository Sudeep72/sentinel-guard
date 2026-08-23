"""Score and baseline comparison endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.models.user import User
from app.schemas.baselines import BaselineComparisonResponse
from app.schemas.scores import SecurityScoreResponse
from app.services.baseline_service import compare_to_baseline
from app.services.score_service import get_security_score

router = APIRouter(prefix="/servers", tags=["scores"])


@router.get("/{server_id}/score", response_model=SecurityScoreResponse)
def get_score(
    server_id: str,
    scan_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecurityScoreResponse:
    """Get the security score for a server's latest (or specified) scan."""
    try:
        return get_security_score(db, server_id=server_id, scan_id=scan_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{server_id}/baseline", response_model=BaselineComparisonResponse)
def get_baseline_comparison(
    server_id: str,
    category: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> BaselineComparisonResponse:
    """Compare a server's current state against its distro's security baseline."""
    try:
        return compare_to_baseline(db, server_id=server_id, category=category)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
