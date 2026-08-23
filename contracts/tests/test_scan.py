from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sentinelguard_contracts import (
    Distro,
    GuardianCategory,
    GuardianResult,
    GuardianRunStatus,
    ScanPayload,
    ScanStatus,
)


def _now():
    return datetime.now(UTC)


def _guardian_result(status: GuardianRunStatus) -> GuardianResult:
    return GuardianResult(
        module=GuardianCategory.PERMISSION,
        status=status,
        collected_at=_now(),
        error_message=None if status == GuardianRunStatus.OK else "boom",
    )


def test_scan_payload_all_ok_requires_completed_status():
    start = _now()
    payload = ScanPayload(
        server_id="srv-1",
        hostname="web01",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=start,
        completed_at=start + timedelta(seconds=5),
        status=ScanStatus.COMPLETED,
        guardian_results=[_guardian_result(GuardianRunStatus.OK)],
    )
    assert payload.status == ScanStatus.COMPLETED


def test_scan_payload_rejects_completed_status_when_guardian_errored():
    start = _now()
    with pytest.raises(ValidationError):
        ScanPayload(
            server_id="srv-1",
            hostname="web01",
            distro=Distro.UBUNTU,
            agent_version="0.1.0",
            started_at=start,
            completed_at=start + timedelta(seconds=5),
            status=ScanStatus.COMPLETED,
            guardian_results=[
                _guardian_result(GuardianRunStatus.OK),
                _guardian_result(GuardianRunStatus.ERROR),
            ],
        )


def test_scan_payload_requires_partial_status_on_mixed_results():
    start = _now()
    payload = ScanPayload(
        server_id="srv-1",
        hostname="web01",
        distro=Distro.UBUNTU,
        agent_version="0.1.0",
        started_at=start,
        completed_at=start + timedelta(seconds=5),
        status=ScanStatus.PARTIAL,
        guardian_results=[
            _guardian_result(GuardianRunStatus.OK),
            _guardian_result(GuardianRunStatus.ERROR),
        ],
    )
    assert payload.status == ScanStatus.PARTIAL


def test_scan_payload_requires_failed_status_when_all_errored():
    start = _now()
    with pytest.raises(ValidationError):
        ScanPayload(
            server_id="srv-1",
            hostname="web01",
            distro=Distro.UBUNTU,
            agent_version="0.1.0",
            started_at=start,
            completed_at=start + timedelta(seconds=5),
            status=ScanStatus.COMPLETED,
            guardian_results=[_guardian_result(GuardianRunStatus.ERROR)],
        )


def test_scan_payload_rejects_completed_before_started():
    start = _now()
    with pytest.raises(ValidationError):
        ScanPayload(
            server_id="srv-1",
            hostname="web01",
            distro=Distro.UBUNTU,
            agent_version="0.1.0",
            started_at=start,
            completed_at=start - timedelta(seconds=1),
            status=ScanStatus.RUNNING,
            guardian_results=[],
        )


def test_scan_payload_allows_none_server_id():
    start = _now()
    payload = ScanPayload(
        server_id=None,
        hostname="web01",
        distro=Distro.UBUNTU,
        agent_version="0.1.0",
        started_at=start,
        completed_at=start,
        status=ScanStatus.RUNNING,
        guardian_results=[],
    )
    assert payload.server_id is None


def test_scan_payload_empty_guardian_results_skips_consistency_check():
    start = _now()
    payload = ScanPayload(
        server_id="srv-1",
        hostname="web01",
        distro=Distro.UBUNTU,
        agent_version="0.1.0",
        started_at=start,
        completed_at=start,
        status=ScanStatus.RUNNING,
        guardian_results=[],
    )
    assert payload.guardian_results == []
