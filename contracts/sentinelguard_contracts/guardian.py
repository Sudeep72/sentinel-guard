"""GuardianResult — the output of a single Guardian collector run."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinelguard_contracts.enums import GuardianCategory, GuardianRunStatus
from sentinelguard_contracts.finding import Finding


class GuardianResult(BaseModel):
    """Result of running one Guardian's ``collect()`` on the host.

    A Guardian that fails to collect (permission denied, missing binary,
    unsupported distro feature, etc.) still returns a ``GuardianResult``
    with ``status=ERROR`` and an ``error_message`` rather than raising —
    this lets a scan report ``PARTIAL`` instead of failing outright when
    one of nine Guardians can't run.

    Attributes:
        module: Which Guardian produced this result.
        status: Whether collection succeeded.
        findings: Findings produced (empty list if none, or if status is ERROR).
        error_message: Populated only when status is ERROR.
        collected_at: UTC timestamp when collection finished.
        duration_ms: How long collection took, for performance monitoring.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    module: GuardianCategory
    status: GuardianRunStatus
    findings: list[Finding] = Field(default_factory=list)
    error_message: str | None = None
    collected_at: datetime
    duration_ms: float | None = Field(default=None, ge=0)
