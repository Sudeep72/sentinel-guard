from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinelguard_contracts import (
    Finding,
    GuardianCategory,
    GuardianResult,
    GuardianRunStatus,
    Severity,
)


def _finding():
    return Finding(
        check_id="PERM-001",
        module=GuardianCategory.PERMISSION,
        title="/etc/shadow is world-readable",
        severity=Severity.CRITICAL,
        description="/etc/shadow has mode 644.",
        why_it_matters="Password hashes become readable by any local user.",
        attack_scenario="A low-privilege user reads the hashes and performs offline cracking.",
        recommendation="Run: chmod 600 /etc/shadow",
        current_value="644",
        expected_value="600",
    )


def test_guardian_result_ok_with_findings():
    result = GuardianResult(
        module=GuardianCategory.PERMISSION,
        status=GuardianRunStatus.OK,
        findings=[_finding()],
        collected_at=datetime.now(UTC),
        duration_ms=42.5,
    )
    assert result.status == GuardianRunStatus.OK
    assert len(result.findings) == 1


def test_guardian_result_ok_with_no_findings():
    result = GuardianResult(
        module=GuardianCategory.PERMISSION,
        status=GuardianRunStatus.OK,
        findings=[],
        collected_at=datetime.now(UTC),
    )
    assert result.findings == []
    assert result.error_message is None


def test_guardian_result_error_state():
    result = GuardianResult(
        module=GuardianCategory.DOCKER,
        status=GuardianRunStatus.ERROR,
        error_message="docker binary not found on host",
        collected_at=datetime.now(UTC),
    )
    assert result.status == GuardianRunStatus.ERROR
    assert result.error_message == "docker binary not found on host"
    assert result.findings == []


def test_guardian_result_rejects_negative_duration():
    with pytest.raises(ValidationError):
        GuardianResult(
            module=GuardianCategory.PERMISSION,
            status=GuardianRunStatus.OK,
            collected_at=datetime.now(UTC),
            duration_ms=-1,
        )


def test_guardian_result_requires_collected_at():
    with pytest.raises(ValidationError):
        GuardianResult(module=GuardianCategory.PERMISSION, status=GuardianRunStatus.OK)
