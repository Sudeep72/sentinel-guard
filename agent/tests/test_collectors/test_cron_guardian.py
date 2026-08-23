"""Tests for the Cron Guardian collector."""

from __future__ import annotations

import os
from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.cron_guardian import CronGuardian


def test_category_is_cron():
    assert CronGuardian.category == GuardianCategory.CRON


def test_run_returns_guardian_result():
    result = CronGuardian().run()
    assert result.module == GuardianCategory.CRON
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


# ── CRON-001: Directory permissions ─────────────────────────────────────────


def test_cron_001_insecure_crontab_permissions(tmp_path):
    crontab = tmp_path / "crontab"
    crontab.write_text("* * * * * root /usr/bin/backup.sh\n")
    os.chmod(crontab, 0o666)  # too permissive

    guardian = CronGuardian()
    fake_checks = [(str(crontab), "0o644")]
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", fake_checks),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_001 = [f for f in findings if f.check_id == "CRON-001"]
    assert len(cron_001) == 1
    assert cron_001[0].severity == Severity.MEDIUM
    assert cron_001[0].expected_value == "0o644"


def test_cron_001_correct_permissions_no_finding(tmp_path):
    crontab = tmp_path / "crontab"
    crontab.write_text("# crontab\n")
    os.chmod(crontab, 0o644)

    guardian = CronGuardian()
    fake_checks = [(str(crontab), "0o644")]
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", fake_checks),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_001 = [f for f in findings if f.check_id == "CRON-001"]
    assert len(cron_001) == 0


def test_cron_001_missing_path_skipped():
    guardian = CronGuardian()
    fake_checks = [("/nonexistent/cron.d", "0o0755")]
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", fake_checks),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    assert findings == []


# ── CRON-002: World-writable cron files ─────────────────────────────────────


def test_cron_002_world_writable_cron_file(tmp_path):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    bad_file = cron_d / "backup"
    bad_file.write_text("0 2 * * * root /usr/bin/backup\n")
    os.chmod(bad_file, 0o777)

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", [str(cron_d)]),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_002 = [f for f in findings if f.check_id == "CRON-002"]
    assert len(cron_002) == 1
    assert cron_002[0].severity == Severity.CRITICAL


def test_cron_002_safe_cron_file_no_finding(tmp_path):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    safe_file = cron_d / "backup"
    safe_file.write_text("0 2 * * * root /usr/bin/backup\n")
    os.chmod(safe_file, 0o644)

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", [str(cron_d)]),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_002 = [f for f in findings if f.check_id == "CRON-002"]
    assert len(cron_002) == 0


# ── CRON-003: World-writable scripts in /etc/crontab ────────────────────────


def test_cron_003_world_writable_crontab_script(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/bash\necho backup\n")
    os.chmod(script, 0o777)

    crontab_content = f"0 2 * * * root {script}\n"

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch(
            "sentinelguard_agent.collectors.cron_guardian.read_file", return_value=crontab_content
        ),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_003 = [f for f in findings if f.check_id == "CRON-003"]
    assert len(cron_003) == 1
    assert cron_003[0].severity == Severity.CRITICAL


def test_cron_003_safe_script_no_finding(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/bash\necho backup\n")
    os.chmod(script, 0o755)

    crontab_content = f"0 2 * * * root {script}\n"

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch(
            "sentinelguard_agent.collectors.cron_guardian.read_file", return_value=crontab_content
        ),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_003 = [f for f in findings if f.check_id == "CRON-003"]
    assert len(cron_003) == 0


# ── CRON-004: Spool permissions ──────────────────────────────────────────────


def test_cron_004_insecure_spool(tmp_path):
    spool = tmp_path / "cron"
    spool.mkdir()
    os.chmod(spool, 0o755)  # too permissive

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.read_file", return_value=None),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", str(spool)),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_004 = [f for f in findings if f.check_id == "CRON-004"]
    assert len(cron_004) == 1
    assert cron_004[0].severity == Severity.MEDIUM


def test_cron_004_correct_spool_no_finding(tmp_path):
    spool = tmp_path / "cron"
    spool.mkdir()
    os.chmod(spool, 0o700)

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.read_file", return_value=None),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", str(spool)),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    cron_004 = [f for f in findings if f.check_id == "CRON-004"]
    assert len(cron_004) == 0


def test_all_findings_have_full_copilot_payload(tmp_path):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    bad = cron_d / "evil"
    bad.write_text("* * * * * root /bin/bash\n")
    os.chmod(bad, 0o777)

    guardian = CronGuardian()
    with (
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_DIR_CHECKS", []),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SCAN_DIRS", [str(cron_d)]),
        patch("sentinelguard_agent.collectors.cron_guardian.read_file", return_value=None),
        patch("sentinelguard_agent.collectors.cron_guardian.CRON_SPOOL_DIR", "/nonexistent"),
        patch("sentinelguard_agent.collectors.cron_guardian.AT_SPOOL_DIR", "/nonexistent"),
    ):
        findings = guardian._collect()

    for f in findings:
        assert f.check_id
        assert f.title
        assert f.description
        assert f.why_it_matters
        assert f.attack_scenario
        assert f.recommendation
        assert f.current_value is not None
        assert f.expected_value is not None


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.CRON in categories
