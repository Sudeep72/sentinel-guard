"""Security scoring models — see ARCHITECTURE.md section 7 for the formula."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinelguard_contracts.enums import GuardianCategory


class CategoryScore(BaseModel):
    """Score for a single Guardian category on a single scan."""

    model_config = ConfigDict(str_strip_whitespace=True)

    category: GuardianCategory
    score: float = Field(ge=0, le=100)
    weight: float = Field(gt=0, le=1)


class SecurityScore(BaseModel):
    """Overall + per-category score for a single scan.

    ``overall_score`` is the weighted average of ``category_scores``
    using each category's ``weight``. Weights across all categories in
    a complete score should sum to 1.0 (validated dashboard-side by the
    Scoring Engine in Phase 18, not enforced here since a partial scan
    may legitimately only cover a subset of categories).
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    scan_id: str
    overall_score: float = Field(ge=0, le=100)
    category_scores: list[CategoryScore] = Field(default_factory=list)
    computed_at: datetime
