"""Aggregator — runs a set of Guardians and merges their results into a
single ``ScanPayload`` ready to submit to the Dashboard.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard_contracts import (
    Distro,
    GuardianResult,
    GuardianRunStatus,
    ScanPayload,
    ScanStatus,
)

from sentinelguard_agent.collectors.base import BaseGuardian


def _determine_status(results: list[GuardianResult]) -> ScanStatus:
    """Derive overall scan status from individual Guardian outcomes.

    - No Guardians ran at all (Phase 3: registry is empty) -> COMPLETED,
      since an empty scan isn't a failure, just a no-op framework run.
    - All Guardians OK -> COMPLETED.
    - Some OK, some ERROR -> PARTIAL.
    - All ERROR -> FAILED.
    """
    if not results:
        return ScanStatus.COMPLETED

    ok_count = sum(1 for r in results if r.status == GuardianRunStatus.OK)
    if ok_count == len(results):
        return ScanStatus.COMPLETED
    if ok_count == 0:
        return ScanStatus.FAILED
    return ScanStatus.PARTIAL


def run_scan(
    guardians: list[BaseGuardian],
    hostname: str,
    distro: Distro,
    distro_version: str | None,
    agent_version: str,
    server_id: str | None = None,
) -> ScanPayload:
    """Run every given Guardian and assemble the resulting ScanPayload.

    Guardians run sequentially in V1 (nine lightweight filesystem/config
    checks don't warrant the complexity of concurrent execution yet;
    revisit if/when Guardian count or per-check cost grows).
    """
    started_at = datetime.now(UTC)
    results = [guardian.run() for guardian in guardians]
    completed_at = datetime.now(UTC)

    return ScanPayload(
        server_id=server_id,
        hostname=hostname,
        distro=distro,
        distro_version=distro_version,
        agent_version=agent_version,
        started_at=started_at,
        completed_at=completed_at,
        status=_determine_status(results),
        guardian_results=results,
    )
