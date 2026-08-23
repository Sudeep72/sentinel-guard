"""Database engine and session management.

V1 uses synchronous SQLAlchemy against SQLite. FastAPI runs sync path
operation functions in a threadpool, so this is a legitimate,
simpler-to-reason-about production pattern for the workload SentinelGuard
v1 handles (periodic agent scan submissions + dashboard reads, not
high-throughput request volume). Revisit for an async engine/driver if
that assumption stops holding.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def _ensure_sqlite_directory_exists(url: str) -> None:
    """Create the parent directory of a SQLite file URL if it doesn't exist.

    SQLite creates the database *file* itself on first connection, but
    it does not create missing parent directories -- ``sqlite3.connect``
    fails with "unable to open database file" if e.g. ``./data/`` isn't
    there yet. This is exactly what happens on a fresh clone, since
    ``data/`` is gitignored (it's runtime state, not source). Skips
    in-memory databases (``:memory:``), which have no file to create.
    """
    parsed = make_url(url)
    if not parsed.drivername.startswith("sqlite"):
        return
    db_path = parsed.database
    if not db_path or db_path == ":memory:":
        return
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine.

    ``check_same_thread=False`` is required for SQLite when the engine
    is shared across FastAPI's threadpool-executed request handlers.
    """
    url = database_url or get_settings().database_url
    _ensure_sqlite_directory_exists(url)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session, closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
