"""Server model — one row per registered agent/host."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Server(Base):
    """A registered host running the SentinelGuard Agent.

    ``api_key_hash`` stores a SHA-256 hash of the per-server API key
    (not bcrypt) — see ``app/auth/security.py`` for why a fast
    deterministic hash is the correct choice for high-entropy API keys,
    as opposed to the adaptive hashing used for human passwords.
    """

    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    distro: Mapped[str] = mapped_column(String(32), nullable=False)
    distro_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="offline")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    def __repr__(self) -> str:  # pragma: no cover - debug convenience only
        return f"<Server id={self.id!r} hostname={self.hostname!r} status={self.status!r}>"
