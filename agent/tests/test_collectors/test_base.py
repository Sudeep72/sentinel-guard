from sentinelguard_contracts import Finding, GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.base import BaseGuardian


class _WorkingGuardian(BaseGuardian):
    category = GuardianCategory.PERMISSION

    def _collect(self) -> list[Finding]:
        return [
            Finding(
                check_id="PERM-001",
                module=GuardianCategory.PERMISSION,
                title="/etc/shadow is world-readable",
                severity=Severity.CRITICAL,
                description="/etc/shadow has mode 644.",
                why_it_matters="Password hashes become readable by any local user.",
                attack_scenario="A low-privilege user reads the hashes and cracks them offline.",
                recommendation="chmod 600 /etc/shadow",
                current_value="644",
                expected_value="600",
            )
        ]


class _EmptyGuardian(BaseGuardian):
    category = GuardianCategory.OWNERSHIP

    def _collect(self) -> list[Finding]:
        return []


class _FailingGuardian(BaseGuardian):
    category = GuardianCategory.DOCKER

    def _collect(self) -> list[Finding]:
        raise RuntimeError("docker binary not found on host")


def test_working_guardian_returns_ok_with_findings():
    result = _WorkingGuardian().run()
    assert result.status == GuardianRunStatus.OK
    assert result.module == GuardianCategory.PERMISSION
    assert len(result.findings) == 1
    assert result.error_message is None
    assert result.duration_ms is not None and result.duration_ms >= 0


def test_guardian_with_no_findings_still_reports_ok():
    result = _EmptyGuardian().run()
    assert result.status == GuardianRunStatus.OK
    assert result.findings == []


def test_failing_guardian_returns_error_result_not_exception():
    result = _FailingGuardian().run()
    assert result.status == GuardianRunStatus.ERROR
    assert result.module == GuardianCategory.DOCKER
    assert result.error_message == "docker binary not found on host"
    assert result.findings == []


def test_failing_guardian_does_not_raise():
    # The whole point of run() wrapping _collect(): this must not raise.
    try:
        _FailingGuardian().run()
    except Exception as exc:  # pragma: no cover - this branch should be unreachable
        raise AssertionError(f"run() should never raise, but raised {exc!r}") from exc


def test_base_guardian_cannot_be_instantiated_directly():
    import pytest

    with pytest.raises(TypeError):
        BaseGuardian()  # type: ignore[abstract]
