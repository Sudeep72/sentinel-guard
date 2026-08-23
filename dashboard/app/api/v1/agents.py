"""Agent-facing endpoints: registration and scan ingestion.

These are the only two endpoints agents call — everything else under
``/api/v1/`` is for human users (JWT-authenticated) or MCP tools acting
on their behalf.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sentinelguard_contracts import ScanPayload, ServerRegistration
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_server
from app.db.session import get_db
from app.models.server import Server
from app.schemas.agents import AgentRegistrationResponse, ScanSubmissionResponse
from app.services.scan_service import ingest_scan
from app.services.server_service import register_server

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post(
    "/register", response_model=AgentRegistrationResponse, status_code=status.HTTP_201_CREATED
)
def register_agent(
    registration: ServerRegistration, db: Session = Depends(get_db)
) -> AgentRegistrationResponse:
    """Register a new host running the SentinelGuard Agent.

    No authentication required for this endpoint (an agent has no
    credentials yet — that's the point of registering). The response's
    ``api_key`` is shown exactly once; the agent must store it.
    """
    server_info, api_key = register_server(db, registration)
    return AgentRegistrationResponse(server=server_info, api_key=api_key)


@router.post("/scans", response_model=ScanSubmissionResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_scan(
    payload: ScanPayload,
    server: Server = Depends(get_current_server),
    db: Session = Depends(get_db),
) -> ScanSubmissionResponse:
    """Submit a completed scan. Requires the server's API key.

    The scan is always attributed to whichever server the API key
    belongs to (see ``ingest_scan``'s docstring) — an agent cannot
    submit data on behalf of a different server_id in the payload.
    """
    scan = ingest_scan(db, server, payload)
    return ScanSubmissionResponse(scan_id=scan.id, status="accepted")
