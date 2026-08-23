from sentinelguard_contracts import Distro, Finding, GuardianCategory, ScanStatus

from sentinelguard_agent.aggregator import run_scan
from sentinelguard_agent.collectors.base import BaseGuardian


class _OkGuardian(BaseGuardian):
    category = GuardianCategory.PERMISSION

    def _collect(self) -> list[Finding]:
        return []


class _AnotherOkGuardian(BaseGuardian):
    category = GuardianCategory.OWNERSHIP

    def _collect(self) -> list[Finding]:
        return []


class _ErrorGuardian(BaseGuardian):
    category = GuardianCategory.DOCKER

    def _collect(self) -> list[Finding]:
        raise RuntimeError("boom")


def _common_kwargs():
    return dict(
        hostname="test-host",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        server_id="srv-1",
    )


def test_run_scan_with_no_guardians_is_completed():
    payload = run_scan(guardians=[], **_common_kwargs())
    assert payload.status == ScanStatus.COMPLETED
    assert payload.guardian_results == []


def test_run_scan_all_ok_is_completed():
    payload = run_scan(guardians=[_OkGuardian(), _AnotherOkGuardian()], **_common_kwargs())
    assert payload.status == ScanStatus.COMPLETED
    assert len(payload.guardian_results) == 2


def test_run_scan_mixed_results_is_partial():
    payload = run_scan(guardians=[_OkGuardian(), _ErrorGuardian()], **_common_kwargs())
    assert payload.status == ScanStatus.PARTIAL


def test_run_scan_all_errors_is_failed():
    payload = run_scan(guardians=[_ErrorGuardian()], **_common_kwargs())
    assert payload.status == ScanStatus.FAILED


def test_run_scan_preserves_scan_metadata():
    payload = run_scan(guardians=[], **_common_kwargs())
    assert payload.hostname == "test-host"
    assert payload.distro == Distro.UBUNTU
    assert payload.distro_version == "24.04"
    assert payload.agent_version == "0.1.0"
    assert payload.server_id == "srv-1"


def test_run_scan_allows_none_server_id():
    kwargs = _common_kwargs()
    kwargs["server_id"] = None
    payload = run_scan(guardians=[], **kwargs)
    assert payload.server_id is None


def test_run_scan_completed_at_not_before_started_at():
    payload = run_scan(guardians=[_OkGuardian()], **_common_kwargs())
    assert payload.completed_at >= payload.started_at
