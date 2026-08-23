"""Shared pytest fixtures for the dashboard test suite.

Every test gets a fresh, isolated in-memory SQLite database (via a
StaticPool single connection so it survives across FastAPI's
threadpool-executed request handlers) — no test can see another test's
data, and nothing touches a real file on disk.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Import models so they're registered on Base.metadata before create_all.
import app.models  # noqa: F401
from app.auth.jwt import create_access_token
from app.auth.security import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.user import User


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine) -> Generator[Session, None, None]:
    session_local = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    session = session_local()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_engine) -> Generator[TestClient, None, None]:
    session_local = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)

    def override_get_db() -> Generator[Session, None, None]:
        session = session_local()
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture()
def admin_user(db_session: Session) -> User:
    user = User(
        email="admin@example.com",
        hashed_password=hash_password("adminpass123"),
        role="admin",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def viewer_user(db_session: Session) -> User:
    user = User(
        email="viewer@example.com", hashed_password=hash_password("viewerpass123"), role="viewer"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_token(admin_user: User) -> str:
    return create_access_token(subject=admin_user.id, extra_claims={"role": admin_user.role})


@pytest.fixture()
def viewer_token(viewer_user: User) -> str:
    return create_access_token(subject=viewer_user.id, extra_claims={"role": viewer_user.role})


@pytest.fixture()
def auth_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}
