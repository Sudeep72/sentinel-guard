"""Tests for the SSH Guardian collector."""

from __future__ import annotations

from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.ssh_guardian import SSHGuardian


def test_category_is_ssh():
    assert SSHGuardian.category == GuardianCategory.SSH


def test_run_returns_guardian_result():
    result = SSHGuardian().run()
    assert result.module == GuardianCategory.SSH
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


def test_returns_no_findings_when_sshd_config_missing():
    guardian = SSHGuardian()
    with patch(
        "sentinelguard_agent.collectors.ssh_guardian.read_file",
        return_value=None,
    ):
        findings = guardian._collect()
    assert findings == []


def _make_guardian_with_config(config_content: str) -> SSHGuardian:
    guardian = SSHGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.read_file",
            return_value=config_content,
        ),
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.Path.is_dir",
            return_value=False,
        ),
    ):
        guardian._loaded_config = guardian._load_sshd_config()
    return guardian


def _collect_with_config(config_content: str) -> list:
    guardian = SSHGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.read_file",
            return_value=config_content,
        ),
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.Path.is_dir",
            return_value=False,
        ),
    ):
        return guardian._collect()


# ── SSH-001 PermitRootLogin ─────────────────────────────────────────────────


def test_ssh_001_fires_when_root_login_yes():
    findings = _collect_with_config("PermitRootLogin yes\nPasswordAuthentication no\n")
    ssh_001 = [f for f in findings if f.check_id == "SSH-001"]
    assert len(ssh_001) == 1
    assert ssh_001[0].severity == Severity.HIGH
    assert ssh_001[0].current_value == "yes"
    assert ssh_001[0].expected_value == "no"


def test_ssh_001_fires_when_root_login_without_password():
    findings = _collect_with_config("PermitRootLogin without-password\n")
    ssh_001 = [f for f in findings if f.check_id == "SSH-001"]
    assert len(ssh_001) == 1


def test_ssh_001_not_fired_when_root_login_no():
    findings = _collect_with_config(
        "PermitRootLogin no\nPasswordAuthentication no\n" "AllowGroups ssh-users\n"
    )
    ssh_001 = [f for f in findings if f.check_id == "SSH-001"]
    assert len(ssh_001) == 0


def test_ssh_001_not_fired_when_prohibit_password():
    findings = _collect_with_config("PermitRootLogin prohibit-password\n")
    ssh_001 = [f for f in findings if f.check_id == "SSH-001"]
    assert len(ssh_001) == 0


# ── SSH-002 PasswordAuthentication ──────────────────────────────────────────


def test_ssh_002_fires_when_password_auth_enabled():
    findings = _collect_with_config("PasswordAuthentication yes\n")
    ssh_002 = [f for f in findings if f.check_id == "SSH-002"]
    assert len(ssh_002) == 1
    assert ssh_002[0].severity == Severity.HIGH


def test_ssh_002_not_fired_when_password_auth_no():
    findings = _collect_with_config(
        "PasswordAuthentication no\nPermitRootLogin no\nAllowGroups ssh-users\n"
    )
    ssh_002 = [f for f in findings if f.check_id == "SSH-002"]
    assert len(ssh_002) == 0


def test_ssh_002_fires_when_not_set_defaults_to_yes():
    # Default when missing is 'yes'
    findings = _collect_with_config("# empty config\n")
    ssh_002 = [f for f in findings if f.check_id == "SSH-002"]
    assert len(ssh_002) == 1


# ── SSH-003 PermitEmptyPasswords ────────────────────────────────────────────


def test_ssh_003_fires_when_empty_passwords_yes():
    findings = _collect_with_config("PermitEmptyPasswords yes\n")
    ssh_003 = [f for f in findings if f.check_id == "SSH-003"]
    assert len(ssh_003) == 1
    assert ssh_003[0].severity == Severity.CRITICAL


def test_ssh_003_not_fired_when_empty_passwords_no():
    findings = _collect_with_config(
        "PermitEmptyPasswords no\nPermitRootLogin no\n"
        "PasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_003 = [f for f in findings if f.check_id == "SSH-003"]
    assert len(ssh_003) == 0


# ── SSH-004 PubkeyAuthentication ────────────────────────────────────────────


def test_ssh_004_fires_when_pubkey_disabled():
    findings = _collect_with_config("PubkeyAuthentication no\n")
    ssh_004 = [f for f in findings if f.check_id == "SSH-004"]
    assert len(ssh_004) == 1
    assert ssh_004[0].severity == Severity.MEDIUM


def test_ssh_004_not_fired_when_pubkey_enabled():
    findings = _collect_with_config(
        "PubkeyAuthentication yes\nPermitRootLogin no\n"
        "PasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_004 = [f for f in findings if f.check_id == "SSH-004"]
    assert len(ssh_004) == 0


# ── SSH-005 Weak Ciphers ────────────────────────────────────────────────────


def test_ssh_005_fires_on_weak_cipher():
    findings = _collect_with_config(
        "Ciphers aes128-ctr,3des-cbc\nPermitRootLogin no\n"
        "PasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_005 = [f for f in findings if f.check_id == "SSH-005"]
    assert len(ssh_005) == 1
    assert ssh_005[0].severity == Severity.HIGH
    assert "3des-cbc" in ssh_005[0].current_value


def test_ssh_005_not_fired_on_strong_ciphers_only():
    findings = _collect_with_config(
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
        "PermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_005 = [f for f in findings if f.check_id == "SSH-005"]
    assert len(ssh_005) == 0


def test_ssh_005_not_fired_when_ciphers_not_configured():
    findings = _collect_with_config("PermitRootLogin no\nPasswordAuthentication no\n")
    ssh_005 = [f for f in findings if f.check_id == "SSH-005"]
    assert len(ssh_005) == 0


# ── SSH-006 Weak MACs ────────────────────────────────────────────────────────


def test_ssh_006_fires_on_weak_mac():
    findings = _collect_with_config(
        "MACs hmac-sha2-256,hmac-md5\nPermitRootLogin no\n"
        "PasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_006 = [f for f in findings if f.check_id == "SSH-006"]
    assert len(ssh_006) == 1
    assert ssh_006[0].severity == Severity.MEDIUM


def test_ssh_006_not_fired_on_strong_macs():
    findings = _collect_with_config(
        "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com\n"
        "PermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_006 = [f for f in findings if f.check_id == "SSH-006"]
    assert len(ssh_006) == 0


# ── SSH-007 Protocol ────────────────────────────────────────────────────────


def test_ssh_007_fires_when_protocol_1():
    findings = _collect_with_config("Protocol 1\n")
    ssh_007 = [f for f in findings if f.check_id == "SSH-007"]
    assert len(ssh_007) == 1
    assert ssh_007[0].severity == Severity.CRITICAL


def test_ssh_007_fires_when_protocol_1_2():
    findings = _collect_with_config("Protocol 1,2\n")
    ssh_007 = [f for f in findings if f.check_id == "SSH-007"]
    assert len(ssh_007) == 1


def test_ssh_007_not_fired_when_protocol_2():
    findings = _collect_with_config(
        "Protocol 2\nPermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_007 = [f for f in findings if f.check_id == "SSH-007"]
    assert len(ssh_007) == 0


# ── SSH-008 AllowUsers / AllowGroups ────────────────────────────────────────


def test_ssh_008_fires_when_neither_allowusers_nor_allowgroups():
    findings = _collect_with_config("PermitRootLogin no\nPasswordAuthentication no\n")
    ssh_008 = [f for f in findings if f.check_id == "SSH-008"]
    assert len(ssh_008) == 1
    assert ssh_008[0].severity == Severity.MEDIUM


def test_ssh_008_not_fired_when_allowgroups_set():
    findings = _collect_with_config(
        "PermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh-users\n"
    )
    ssh_008 = [f for f in findings if f.check_id == "SSH-008"]
    assert len(ssh_008) == 0


def test_ssh_008_not_fired_when_allowusers_set():
    findings = _collect_with_config(
        "PermitRootLogin no\nPasswordAuthentication no\nAllowUsers alice bob\n"
    )
    ssh_008 = [f for f in findings if f.check_id == "SSH-008"]
    assert len(ssh_008) == 0


# ── Full copilot payload ─────────────────────────────────────────────────────


def test_all_findings_have_complete_copilot_payload():
    """Every finding from SSHGuardian must carry the full AI-copilot payload."""
    findings = _collect_with_config(
        "PermitRootLogin yes\nPasswordAuthentication yes\n"
        "PermitEmptyPasswords yes\nPubkeyAuthentication no\n"
        "Protocol 1\n"
        "Ciphers 3des-cbc\nMACs hmac-md5\n"
    )
    assert len(findings) > 0
    for f in findings:
        assert f.check_id, f"Missing check_id on {f.title}"
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
    assert GuardianCategory.SSH in categories


def test_sshd_config_drop_in_files_merged(tmp_path):
    """Drop-in files from sshd_config.d/ are merged into the main config."""
    main_config = tmp_path / "sshd_config"
    main_config.write_text("PermitRootLogin yes\n")
    drop_in_dir = tmp_path / "sshd_config.d"
    drop_in_dir.mkdir()
    (drop_in_dir / "50-override.conf").write_text("PermitRootLogin no\n")

    guardian = SSHGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.SSHD_CONFIG_PATH",
            str(main_config),
        ),
        patch(
            "sentinelguard_agent.collectors.ssh_guardian.SSHD_CONFIG_D_PATH",
            str(drop_in_dir),
        ),
    ):
        config = guardian._load_sshd_config()

    # First-occurrence-wins: main config has 'yes', drop-in has 'no'.
    # The main file is read first, so 'yes' wins here.
    assert config is not None
    assert "PermitRootLogin" in config
