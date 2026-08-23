"""Tests for the Permission Guardian collector.

Uses a fake filesystem rooted in a tmp_path so no root access is needed
and tests are fully reproducible in CI.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.permission_guardian import (
    PERMISSION_CHECKS,
    PermissionGuardian,
)


def test_category_is_permission():
    assert PermissionGuardian.category == GuardianCategory.PERMISSION


def test_run_returns_guardian_result():
    guardian = PermissionGuardian()
    result = guardian.run()
    assert result.module == GuardianCategory.PERMISSION
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


def test_no_findings_on_ideal_permissions(tmp_path):
    """When all sensitive files have correct permissions, no PERM-001 findings."""
    guardian = PermissionGuardian()

    # Patch PERMISSION_CHECKS to use tmp files with correct modes
    fake_checks = []
    for path_str, expected_octal, severity in PERMISSION_CHECKS:
        fake_file = tmp_path / Path(path_str).name
        fake_file.write_text("content")
        mode = int(expected_octal, 8)
        os.chmod(fake_file, mode)
        fake_checks.append((str(fake_file), expected_octal, severity))

    with patch(
        "sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS",
        fake_checks,
    ):
        with patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ):
            with patch(
                "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
                [],
            ):
                findings = guardian._collect()

    perm_001 = [f for f in findings if f.check_id == "PERM-001"]
    assert len(perm_001) == 0


def test_perm_001_detected_on_insecure_shadow(tmp_path):
    """PERM-001 fires when /etc/shadow has wrong permissions."""
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$hash:...\n")
    os.chmod(shadow, 0o644)  # world-readable — wrong

    fake_checks = [(str(shadow), "0o0600", Severity.CRITICAL)]
    guardian = PermissionGuardian()

    with patch(
        "sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS",
        fake_checks,
    ):
        with patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ):
            with patch(
                "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
                [],
            ):
                findings = guardian._collect()

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "PERM-001"
    assert f.severity == Severity.CRITICAL
    assert f.module == GuardianCategory.PERMISSION
    assert f.current_value is not None
    assert f.expected_value == "0o0600"
    assert "chmod" in f.recommendation.lower()


def test_perm_001_finding_has_full_copilot_payload(tmp_path):
    """Every PERM-001 finding must carry all AI-copilot fields."""
    shadow = tmp_path / "shadow"
    shadow.write_text("content")
    os.chmod(shadow, 0o644)

    fake_checks = [(str(shadow), "0o0600", Severity.CRITICAL)]
    guardian = PermissionGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS",
            fake_checks,
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [],
        ),
    ):
        findings = guardian._collect()

    assert len(findings) == 1
    f = findings[0]
    assert f.title
    assert f.description
    assert f.why_it_matters
    assert f.attack_scenario
    assert f.recommendation
    assert f.current_value
    assert f.expected_value


def test_perm_002_world_writable_file_detected(tmp_path):
    """PERM-002 fires on world-writable files in scanned roots."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    world_writable = etc_dir / "world_writable.conf"
    world_writable.write_text("content")
    os.chmod(world_writable, 0o777)

    guardian = PermissionGuardian()
    with (
        patch("sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [str(etc_dir)],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [],
        ),
    ):
        findings = guardian._collect()

    perm_002 = [f for f in findings if f.check_id == "PERM-002"]
    assert len(perm_002) == 1
    assert perm_002[0].severity == Severity.HIGH


def test_perm_002_not_triggered_for_non_world_writable(tmp_path):
    """PERM-002 does not fire when files are not world-writable."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    normal_file = etc_dir / "normal.conf"
    normal_file.write_text("content")
    os.chmod(normal_file, 0o644)

    guardian = PermissionGuardian()
    with (
        patch("sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [str(etc_dir)],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [],
        ),
    ):
        findings = guardian._collect()

    assert all(f.check_id != "PERM-002" for f in findings)


def test_perm_003_world_readable_sensitive_file(tmp_path):
    """PERM-003 fires when a sensitive file is world-readable."""
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$hash\n")
    os.chmod(shadow, 0o644)  # world-readable

    guardian = PermissionGuardian()
    with (
        patch("sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [(str(shadow), Severity.CRITICAL)],
        ),
    ):
        findings = guardian._collect()

    perm_003 = [f for f in findings if f.check_id == "PERM-003"]
    assert len(perm_003) == 1
    assert perm_003[0].severity == Severity.CRITICAL


def test_perm_003_not_triggered_when_not_world_readable(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$hash\n")
    os.chmod(shadow, 0o640)  # not world-readable

    guardian = PermissionGuardian()
    with (
        patch("sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [(str(shadow), Severity.CRITICAL)],
        ),
    ):
        findings = guardian._collect()

    assert all(f.check_id != "PERM-003" for f in findings)


def test_missing_files_produce_no_findings(tmp_path):
    """If a checked path doesn't exist, no finding is produced."""
    fake_checks = [("/nonexistent/path/shadow", "0o0600", Severity.CRITICAL)]
    guardian = PermissionGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.permission_guardian.PERMISSION_CHECKS",
            fake_checks,
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian.WORLD_WRITABLE_SCAN_ROOTS",
            [],
        ),
        patch(
            "sentinelguard_agent.collectors.permission_guardian._SENSITIVE_WORLD_READABLE",
            [],
        ),
    ):
        findings = guardian._collect()

    assert findings == []


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.PERMISSION in categories
