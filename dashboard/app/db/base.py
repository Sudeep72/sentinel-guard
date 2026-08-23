"""SQLAlchemy declarative base.

Kept in its own module (rather than in ``session.py``) so
``app/db/migrations/env.py`` can import ``Base.metadata`` for Alembic
autogenerate without also importing engine/session setup.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
