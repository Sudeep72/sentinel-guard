"""Baseline comparison response wrapper.

The Baseline Engine lands in Phase 17. Until baselines are seeded, this
lets every caller represent "not available yet" explicitly.
"""

from __future__ import annotations

from pydantic import BaseModel


class BaselineComparisonItem(BaseModel):
    """A single rule's current-vs-expected comparison."""

    category: str
    rule: str
    current_value: str | None = None
    expected_value: str | None = None
    matches_baseline: bool


class BaselineComparisonResponse(BaseModel):
    """Wraps baseline comparison results with an explicit availability flag."""

    available: bool
    server_id: str
    distro: str
    comparisons: list[BaselineComparisonItem] = []
    message: str | None = None
