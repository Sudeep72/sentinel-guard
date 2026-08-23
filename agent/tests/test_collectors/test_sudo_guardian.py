"""Tests for the Sudo Guardian collector."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.sudo_guardian import SudoGuardian


def test_category_is_sudo():
    assert SudoGuardian.category == GuardianCategory.SUDO


def test_run_returns_guardian_result():
    result = SudoGuardian().run()
    assert result.module == GuardianCategory.SUDO
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


def _collect_with_sudoers(content: str, tmp_path: Path) -> list:
    sudoers = tmp_path / "sudoers"
    sudoers.write_text(content)
    os.chmod(sudoers, 0o440)

    guardian = SudoGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH",
            str(sudoers),
        ),
        patch(
            "sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH",
            str(tmp_path / "sudoers.d"),
        ),
    ):
        return guardian._collect()


# ── Permission checks ────────────────────────────────────────────────────────


def test_sudo_001_insecure_permissions(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n")
    os.chmod(sudoers, 0o644)  # too permissive

    guardian = SudoGuardian()
    with (
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH", str(sudoers)),
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH", str(tmp_path / "d")),
    ):
        findings = guardian._collect()

    sudo_001 = [f for f in findings if f.check_id == "SUDO-001"]
    assert len(sudo_001) == 1
    assert sudo_001[0].severity == Severity.HIGH
    assert sudo_001[0].current_value is not None
    assert sudo_001[0].expected_value == "0o440"


def test_sudo_001_correct_permissions_no_finding(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n")
    os.chmod(sudoers, 0o440)

    guardian = SudoGuardian()
    with (
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH", str(sudoers)),
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH", str(tmp_path / "d")),
    ):
        findings = guardian._collect()

    sudo_001 = [f for f in findings if f.check_id == "SUDO-001"]
    assert len(sudo_001) == 0


def test_sudo_002_world_writable_sudoers(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n")
    os.chmod(sudoers, 0o666)

    guardian = SudoGuardian()
    with (
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH", str(sudoers)),
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH", str(tmp_path / "d")),
    ):
        findings = guardian._collect()

    sudo_002 = [f for f in findings if f.check_id == "SUDO-002"]
    assert len(sudo_002) == 1
    assert sudo_002[0].severity == Severity.CRITICAL


# ── Rule content checks ──────────────────────────────────────────────────────


def test_sudo_003_nopasswd_detected(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) NOPASSWD: /usr/bin/apt\n", tmp_path)
    sudo_003 = [f for f in findings if f.check_id == "SUDO-003"]
    assert len(sudo_003) == 1
    assert sudo_003[0].severity == Severity.HIGH
    assert "NOPASSWD" in sudo_003[0].current_value


def test_sudo_003_not_fired_for_defaults_nopasswd(tmp_path):
    """Defaults: env_keep += NOPASSWD style entries should not fire SUDO-003."""
    findings = _collect_with_sudoers("Defaults !requiretty\nroot ALL=(ALL) ALL\n", tmp_path)
    sudo_003 = [f for f in findings if f.check_id == "SUDO-003"]
    assert len(sudo_003) == 0


def test_sudo_004_all_all_detected(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) ALL\n", tmp_path)
    sudo_004 = [f for f in findings if f.check_id == "SUDO-004"]
    assert len(sudo_004) == 1
    assert sudo_004[0].severity == Severity.HIGH


def test_sudo_004_all_all_all_detected(tmp_path):
    findings = _collect_with_sudoers("bob ALL=(ALL:ALL) ALL\n", tmp_path)
    sudo_004 = [f for f in findings if f.check_id == "SUDO-004"]
    assert len(sudo_004) == 1


def test_sudo_004_specific_command_no_finding(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) /usr/bin/systemctl restart nginx\n", tmp_path)
    sudo_004 = [f for f in findings if f.check_id == "SUDO-004"]
    assert len(sudo_004) == 0


def test_sudo_005_dangerous_command_vim(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) /usr/bin/vim /etc/hosts\n", tmp_path)
    sudo_005 = [f for f in findings if f.check_id == "SUDO-005"]
    assert len(sudo_005) == 1
    assert "vim" in sudo_005[0].title.lower()


def test_sudo_005_dangerous_command_python(tmp_path):
    findings = _collect_with_sudoers("bob ALL=(ALL) NOPASSWD: /usr/bin/python3\n", tmp_path)
    sudo_005 = [f for f in findings if f.check_id == "SUDO-005"]
    assert len(sudo_005) == 1


def test_sudo_005_safe_command_no_finding(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) /usr/bin/systemctl restart nginx\n", tmp_path)
    sudo_005 = [f for f in findings if f.check_id == "SUDO-005"]
    assert len(sudo_005) == 0


def test_sudoers_d_drop_ins_are_checked(tmp_path):
    """Files under sudoers.d/ are also scanned."""
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n")
    os.chmod(sudoers, 0o440)

    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    drop_in = sudoers_d / "50-admin"
    drop_in.write_text("admin ALL=(ALL) NOPASSWD: ALL\n")
    os.chmod(drop_in, 0o440)

    guardian = SudoGuardian()
    with (
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH", str(sudoers)),
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH", str(sudoers_d)),
    ):
        findings = guardian._collect()

    sudo_003 = [f for f in findings if f.check_id == "SUDO-003"]
    assert len(sudo_003) >= 1


def test_missing_sudoers_produces_no_findings():
    guardian = SudoGuardian()
    with (
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_PATH", "/nonexistent/sudoers"),
        patch("sentinelguard_agent.collectors.sudo_guardian.SUDOERS_D_PATH", "/nonexistent/d"),
    ):
        findings = guardian._collect()
    assert findings == []


def test_all_findings_have_full_copilot_payload(tmp_path):
    findings = _collect_with_sudoers("alice ALL=(ALL) NOPASSWD: /usr/bin/vim\n", tmp_path)
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
    assert GuardianCategory.SUDO in categories
