"""Server fleet endpoints — list/detail for the multi-agent fleet, plus
per-server scan history.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sentinelguard_contracts import ServerInfo
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.models.user import User
from app.schemas.scans import ScanSummary
from app.services.scan_service import list_scans_for_server
from app.services.server_service import get_server, list_servers

router = APIRouter(prefix="/servers", tags=["servers"])


@router.get("", response_model=list[ServerInfo])
def get_servers(
    db: Session = Depends(get_db), _: User = Depends(get_current_user)
) -> list[ServerInfo]:
    """List every registered server in the fleet."""
    return list_servers(db)


@router.get("/{server_id}", response_model=ServerInfo)
def get_server_detail(
    server_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)
) -> ServerInfo:
    """Fetch a single server by id."""
    try:
        return get_server(db, server_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{server_id}/scans", response_model=list[ScanSummary])
def get_server_scans(
    server_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)
) -> list[ScanSummary]:
    """List scan history for a server, most recent first."""
    # Confirms the server exists (404s cleanly) before listing its scans.
    try:
        get_server(db, server_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    scans = list_scans_for_server(db, server_id)
    return [ScanSummary.model_validate(s) for s in scans]
