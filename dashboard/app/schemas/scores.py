"""Score response wrapper.

Extends the shared ``SecurityScore`` contract shape with dashboard-only
summary metadata (pass/fail/total check counts, which baseline version
produced the score) — the same "extend, don't mutate the shared
contract" pattern used by ``FindingRecord``.
"""

from __future__ import annotations

from pydantic import BaseModel
from sentinelguard_contracts import SecurityScore


class SecurityScoreResponse(BaseModel):
    """Wraps a SecurityScore with an explicit availability flag and summary counts."""

    available: bool
    score: SecurityScore | None = None
    message: str | None = None
    total_checks: int | None = None
    passed_checks: int | None = None
    failed_checks: int | None = None
    baseline_version: str | None = None
