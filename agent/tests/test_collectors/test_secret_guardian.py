"""Tests for the Secret Guardian collector."""

from __future__ import annotations

import os
from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.secret_guardian import (
    SecretGuardian,
)


def test_category_is_secret():
    assert SecretGuardian.category == GuardianCategory.SECRET


def test_run_returns_guardian_result():
    result = SecretGuardian().run()
    assert result.module == GuardianCategory.SECRET
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


# ── SECRET-001: SSH private keys ─────────────────────────────────────────────


def test_secret_001_detects_rsa_private_key(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    key_file = ssh_dir / "id_rsa"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    )
    os.chmod(key_file, 0o644)

    guardian = SecretGuardian()
    with (
        patch.object(guardian, "_home_ssh_dirs", return_value=[str(ssh_dir)]),
        patch("sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS", []),
    ):
        findings = guardian._scan_for_ssh_private_keys()

    secret_001 = [f for f in findings if f.check_id == "SECRET-001"]
    assert len(secret_001) == 1
    assert secret_001[0].severity == Severity.CRITICAL
    assert str(key_file) in secret_001[0].title


def test_secret_001_detects_openssh_private_key(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    key_file = ssh_dir / "id_ed25519"
    key_file.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1...\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    guardian = SecretGuardian()
    with (
        patch.object(guardian, "_home_ssh_dirs", return_value=[str(ssh_dir)]),
        patch("sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS", []),
    ):
        findings = guardian._scan_for_ssh_private_keys()

    assert any(f.check_id == "SECRET-001" for f in findings)


def test_secret_001_not_fired_for_public_key(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    pub_file = ssh_dir / "id_rsa.pub"
    pub_file.write_text("ssh-rsa AAAAB3NzaC1yc2E... user@host\n")

    guardian = SecretGuardian()
    with (
        patch.object(guardian, "_home_ssh_dirs", return_value=[str(ssh_dir)]),
        patch("sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS", []),
    ):
        findings = guardian._scan_for_ssh_private_keys()

    assert all(f.check_id != "SECRET-001" for f in findings)


def test_secret_001_only_one_finding_per_file(tmp_path):
    """A file with multiple key headers still produces only one finding."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    key_file = ssh_dir / "multi_key"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n"
        "-----BEGIN EC PRIVATE KEY-----\ndata2\n-----END EC PRIVATE KEY-----\n"
    )

    guardian = SecretGuardian()
    with (
        patch.object(guardian, "_home_ssh_dirs", return_value=[str(ssh_dir)]),
        patch("sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS", []),
    ):
        findings = guardian._scan_for_ssh_private_keys()

    # Only one finding per file (break after first header match)
    files_found = {f.title for f in findings if f.check_id == "SECRET-001"}
    assert len(files_found) == 1


# ── SECRET-002: .env files ───────────────────────────────────────────────────


def test_secret_002_detects_env_file_with_credentials(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DATABASE_URL=postgres://user:pass@localhost/db\n"
        "SECRET_KEY=supersecretvalue123\n"
        "API_TOKEN=myapitoken12345678\n"
    )

    guardian = SecretGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
            [(str(tmp_path), 1)],
        ),
        patch.object(guardian, "_scan_for_secrets_in_files", return_value=[]),
        patch.object(guardian, "_scan_for_ssh_private_keys", return_value=[]),
    ):
        findings = guardian._scan_for_env_files()

    secret_002 = [f for f in findings if f.check_id == "SECRET-002"]
    assert len(secret_002) == 1
    assert secret_002[0].severity == Severity.HIGH
    assert "***" in secret_002[0].current_value


def test_secret_002_detects_env_production_file(tmp_path):
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET_KEY=productiontokenabc12345\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_env_files()

    secret_002 = [f for f in findings if f.check_id == "SECRET-002"]
    assert len(secret_002) == 1


def test_secret_002_not_fired_for_non_env_file(tmp_path):
    config = tmp_path / "config.ini"
    config.write_text("password=mysecret\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_env_files()

    assert all(f.check_id != "SECRET-002" for f in findings)


def test_secret_002_not_fired_for_env_without_secrets(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=production\nDEBUG=false\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_env_files()

    secret_002 = [f for f in findings if f.check_id == "SECRET-002"]
    assert len(secret_002) == 0


# ── SECRET-003: Pattern scanning ────────────────────────────────────────────


def test_secret_003_detects_aws_access_key(tmp_path):
    config_file = tmp_path / "aws.conf"
    config_file.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

    guardian = SecretGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
            [(str(tmp_path), 1)],
        ),
        patch.object(guardian, "_scan_for_ssh_private_keys", return_value=[]),
        patch.object(guardian, "_scan_for_env_files", return_value=[]),
    ):
        findings = guardian._scan_for_secrets_in_files()

    secret_003 = [f for f in findings if f.check_id == "SECRET-003"]
    assert len(secret_003) >= 1
    assert any("AWS" in f.title for f in secret_003)
    # Redacted value should not contain the full key
    for f in secret_003:
        assert f.current_value is not None
        assert len(f.current_value) < 100  # redacted, not full key


def test_secret_003_detects_github_token(tmp_path):
    config_file = tmp_path / "ci.yml"
    config_file.write_text("github_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_secrets_in_files()

    secret_003 = [f for f in findings if f.check_id == "SECRET-003"]
    assert any("GitHub" in f.title for f in secret_003)


def test_secret_003_detects_stripe_key(tmp_path):
    config_file = tmp_path / "payment.conf"
    config_file.write_text("STRIPE_KEY=sk_test_FAKE_FAKE_SENTINELGUARD_TEST_KEY_12345\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_secrets_in_files()

    secret_003 = [f for f in findings if f.check_id == "SECRET-003"]
    assert any("Stripe" in f.title for f in secret_003)


def test_secret_003_skips_binary_extensions(tmp_path):
    binary_file = tmp_path / "image.jpg"
    binary_file.write_bytes(b"\xff\xd8\xff" + b"AKIAIOSFODNN7EXAMPLE")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_secrets_in_files()

    # .jpg files are skipped entirely — no finding should reference image.jpg
    jpg_findings = [f for f in findings if "image.jpg" in f.title]
    assert len(jpg_findings) == 0


def test_secret_003_skips_large_files(tmp_path):
    large_file = tmp_path / "big.log"
    # Write > 512KB of content containing a pattern
    large_file.write_text("A" * 600_000 + "\nAKIAIOSFODNN7EXAMPLE\n")

    guardian = SecretGuardian()
    with patch(
        "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
        [(str(tmp_path), 1)],
    ):
        findings = guardian._scan_for_secrets_in_files()

    large_findings = [f for f in findings if "big.log" in f.title]
    assert len(large_findings) == 0


# ── Severity classification ──────────────────────────────────────────────────


def test_severity_for_aws_key_is_critical():
    guardian = SecretGuardian()
    assert guardian._severity_for_label("AWS Access Key ID") == Severity.CRITICAL
    assert guardian._severity_for_label("AWS Secret Access Key") == Severity.CRITICAL


def test_severity_for_github_token_is_high():
    guardian = SecretGuardian()
    assert guardian._severity_for_label("GitHub Personal Access Token") == Severity.HIGH


def test_severity_for_generic_is_medium():
    guardian = SecretGuardian()
    assert guardian._severity_for_label("Generic API Key") == Severity.MEDIUM


# ── Full copilot payload ─────────────────────────────────────────────────────


def test_all_findings_have_full_copilot_payload(tmp_path):
    key_file = tmp_path / "credentials"
    key_file.write_text("AKIAIOSFODNN7EXAMPLE\n")

    guardian = SecretGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.secret_guardian.SECRET_SCAN_DIRS",
            [(str(tmp_path), 1)],
        ),
        patch.object(guardian, "_scan_for_ssh_private_keys", return_value=[]),
        patch.object(guardian, "_scan_for_env_files", return_value=[]),
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


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.SECRET in categories
