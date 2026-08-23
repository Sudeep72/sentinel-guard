"""Tests for the Ownership Guardian collector."""

from __future__ import annotations

import os
from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.ownership_guardian import (
    OwnershipGuardian,
)


def test_category_is_ownership():
    assert OwnershipGuardian.category == GuardianCategory.OWNERSHIP


def test_run_returns_guardian_result():
    result = OwnershipGuardian().run()
    assert result.module == GuardianCategory.OWNERSHIP
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


def test_own_001_correct_ownership_no_finding(tmp_path):
    """OWN-001 does not fire when uid/gid match expectations."""
    f = tmp_path / "shadow"
    f.write_text("content")
    current_uid = os.getuid()
    current_gid = os.getgid()

    fake_checks = [(str(f), current_uid, current_gid, Severity.CRITICAL)]
    guardian = OwnershipGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS",
            fake_checks,
        ),
        patch("sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS", []),
    ):
        findings = guardian._collect()

    own_001 = [f for f in findings if f.check_id == "OWN-001"]
    assert len(own_001) == 0


def test_own_001_wrong_uid_triggers_finding(tmp_path):
    """OWN-001 fires when the file uid doesn't match the expected value."""
    f = tmp_path / "passwd"
    f.write_text("content")
    current_uid = os.getuid()

    # Expect a different uid than what the file has
    wrong_uid = current_uid + 9999
    fake_checks = [(str(f), wrong_uid, None, Severity.HIGH)]
    guardian = OwnershipGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS",
            fake_checks,
        ),
        patch("sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS", []),
    ):
        findings = guardian._collect()

    own_001 = [f for f in findings if f.check_id == "OWN-001"]
    assert len(own_001) == 1
    assert own_001[0].severity == Severity.HIGH
    assert str(wrong_uid) in own_001[0].expected_value


def test_own_001_finding_full_copilot_payload(tmp_path):
    """Every OWN-001 finding must carry all AI-copilot fields."""
    f = tmp_path / "shadow"
    f.write_text("content")
    fake_checks = [(str(f), 9999, 9999, Severity.CRITICAL)]
    guardian = OwnershipGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS",
            fake_checks,
        ),
        patch("sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS", []),
    ):
        findings = guardian._collect()

    assert len(findings) == 1
    f_obj = findings[0]
    assert f_obj.title
    assert f_obj.description
    assert f_obj.why_it_matters
    assert f_obj.attack_scenario
    assert f_obj.recommendation
    assert f_obj.current_value
    assert f_obj.expected_value


def test_own_001_missing_path_produces_no_finding():
    """If a checked path doesn't exist, skip it silently."""
    fake_checks = [("/nonexistent/path/shadow", 0, 0, Severity.CRITICAL)]
    guardian = OwnershipGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS",
            fake_checks,
        ),
        patch("sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS", []),
    ):
        findings = guardian._collect()

    assert findings == []


def test_own_001_none_expected_uid_accepted(tmp_path):
    """When expected_uid is None, any uid is accepted."""
    f = tmp_path / "shadow"
    f.write_text("content")
    current_gid = os.getgid()
    wrong_gid = current_gid + 9999

    # uid=None means "any", gid wrong — should fire due to gid mismatch
    fake_checks = [(str(f), None, wrong_gid, Severity.HIGH)]
    guardian = OwnershipGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS",
            fake_checks,
        ),
        patch("sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS", []),
    ):
        findings = guardian._collect()

    own_001 = [f for f in findings if f.check_id == "OWN-001"]
    assert len(own_001) == 1


def test_own_002_orphaned_file_detected(tmp_path):
    """OWN-002 fires when a file has a uid with no matching system account."""
    orphan_file = tmp_path / "orphaned.conf"
    orphan_file.write_text("content")

    guardian = OwnershipGuardian()
    with (
        patch("sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS",
            [str(tmp_path)],
        ),
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.file_owner_ids",
            return_value=(99999, 99999),  # uid/gid that definitely don't exist
        ),
    ):
        findings = guardian._collect()

    own_002 = [f for f in findings if f.check_id == "OWN-002"]
    assert len(own_002) >= 1
    assert own_002[0].severity == Severity.MEDIUM


def test_own_002_normal_ownership_not_flagged(tmp_path):
    """OWN-002 does not fire when uid/gid exist in system accounts."""
    normal_file = tmp_path / "normal.conf"
    normal_file.write_text("content")

    current_uid = os.getuid()
    current_gid = os.getgid()

    guardian = OwnershipGuardian()
    with (
        patch("sentinelguard_agent.collectors.ownership_guardian.OWNERSHIP_CHECKS", []),
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.ORPHAN_SCAN_ROOTS",
            [str(tmp_path)],
        ),
        patch(
            "sentinelguard_agent.collectors.ownership_guardian.file_owner_ids",
            return_value=(current_uid, current_gid),
        ),
    ):
        findings = guardian._collect()

    own_002 = [f for f in findings if f.check_id == "OWN-002"]
    assert len(own_002) == 0


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.OWNERSHIP in categories
