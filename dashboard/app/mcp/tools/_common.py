"""Shared DB session helper for MCP tools.

MCP tool calls aren't inside FastAPI's request lifecycle, so they don't
get ``Depends(get_db)`` for free — each tool opens and closes its own
session via this context manager instead, calling into exactly the
same ``app/services/`` functions the REST layer uses.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy.orm import Session

from app.db.session import SessionLocal


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Open a database session for the duration of one MCP tool call."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
