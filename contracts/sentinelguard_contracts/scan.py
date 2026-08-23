"""ScanPayload — the top-level object an agent submits after a scan run."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinelguard_contracts.enums import Distro, ScanStatus
from sentinelguard_contracts.guardian import GuardianResult


class ScanPayload(BaseModel):
    """The full payload an agent POSTs to the dashboard after a scan.

    Attributes:
        server_id: Dashboard-issued server id. ``None`` is only valid
            when submitted alongside a registration in the same request
            flow; standalone scan submissions require a known server_id.
        hostname: Hostname at scan time (kept even though server_id is
            authoritative, useful for audit/debugging).
        distro / distro_version: Detected distro at scan time.
        agent_version: Version of the agent that produced this scan.
        started_at / completed_at: Scan window.
        status: Overall scan outcome — COMPLETED only if every Guardian
            returned OK; PARTIAL if some failed; FAILED if none succeeded.
        guardian_results: One entry per Guardian that was run.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    server_id: str | None = None
    hostname: str = Field(min_length=1, max_length=255)
    distro: Distro
    distro_version: str | None = None
    agent_version: str = Field(min_length=1)
    started_at: datetime
    completed_at: datetime
    status: ScanStatus
    guardian_results: list[GuardianResult] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_time_window(self) -> ScanPayload:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be earlier than started_at")
        return self

    @model_validator(mode="after")
    def _validate_status_consistency(self) -> ScanPayload:
        from sentinelguard_contracts.enums import GuardianRunStatus

        if not self.guardian_results:
            return self
        ok_count = sum(1 for r in self.guardian_results if r.status == GuardianRunStatus.OK)
        error_count = len(self.guardian_results) - ok_count
        if ok_count == 0 and self.status != ScanStatus.FAILED:
            raise ValueError("status must be FAILED when no guardians succeeded")
        if ok_count > 0 and error_count > 0 and self.status != ScanStatus.PARTIAL:
            raise ValueError("status must be PARTIAL when some (not all) guardians succeeded")
        if error_count == 0 and self.status not in (ScanStatus.COMPLETED, ScanStatus.RUNNING):
            raise ValueError("status must be COMPLETED when all guardians succeeded")
        return self
