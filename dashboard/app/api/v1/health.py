"""Health check endpoint — used by both the REST clients and the MCP
``health`` tool (via the same underlying check function)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_db

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Dashboard health status."""

    status: str
    database: str


def check_health(db: Session) -> HealthResponse:
    """Check dashboard health, including database connectivity.

    Shared by the REST ``/health`` endpoint and the MCP ``health`` tool
    so both report identically.
    """
    try:
        db.execute(text("SELECT 1"))
        database_status = "ok"
    except Exception:  # noqa: BLE001 - health check must never raise
        database_status = "unreachable"

    overall = "ok" if database_status == "ok" else "degraded"
    return HealthResponse(status=overall, database=database_status)


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)) -> HealthResponse:
    """Report dashboard health. No authentication required."""
    return check_health(db)
