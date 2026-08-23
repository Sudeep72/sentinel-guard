"""Baseline model — the durable, queryable snapshot of security baseline
rules, populated from YAML by the Baseline Engine (Phase 17).

Each row is one (distro, category) rule set. The ``source`` column is
the extension point for future organization-specific baseline
overrides: ``"yaml"`` rows are synced from the canonical YAML files
in ``app/baselines/``; a future custom-baseline management feature
would write ``"custom"`` rows here, which
``baseline_engine_service.get_effective_rules()`` layers on top of the
YAML defaults.
"""

from __future__ import annotations

import uuid

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Baseline(Base):
    """A distro-specific expected-secure-state rule set for one category."""

    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    distro: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    distro_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rules_json: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="yaml", index=True)
