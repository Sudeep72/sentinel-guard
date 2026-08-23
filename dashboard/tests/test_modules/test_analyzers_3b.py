"""Tests for Sudo, Cron, and Secret dashboard-side analyzers."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard_contracts import FindingStatus, GuardianCategory, Severity

from app.modules.cron.analyzer import CronAnalyzer
from app.modules.secret.analyzer import SecretAnalyzer
from app.modules.sudo.analyzer import SudoAnalyzer
from app.schemas.findings import FindingRecord


def _finding(
    check_id: str,
    module: GuardianCategory,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    current_value: str | None = "violation",
    expected_value: str | None = "expected",
) -> FindingRecord:
    return FindingRecord(
        id="test-id",
        scan_id="scan-id",
        server_id="server-id",
        check_id=check_id,
        module=module,
        title=title,
        severity=severity,
        description="desc",
        why_it_matters="matters",
        attack_scenario="scenario",
        recommendation="fix it",
        current_value=current_value,
        expected_value=expected_value,
        status=FindingStatus.OPEN,
        created_at=datetime.now(UTC),
    )


# ── SudoAnalyzer ─────────────────────────────────────────────────────────────


class TestSudoAnalyzer:
    def setup_method(self):
        self.analyzer = SudoAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.SUDO

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_baseline_severity(self):
        finding = _finding("SUDO-003", GuardianCategory.SUDO, severity=Severity.MEDIUM)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1
        # Ubuntu baseline marks nopasswd_rules as HIGH
        assert result[0].severity == Severity.HIGH

    def test_analyze_keeps_findings_for_unknown_distro(self):
        finding = _finding("SUDO-003", GuardianCategory.SUDO)
        result = self.analyzer.analyze([finding], "windows", None)
        assert len(result) == 1

    def test_analyze_returns_all_findings(self):
        """Sudo analyzer does not suppress findings (unlike permission) — every finding kept."""
        findings = [
            _finding("SUDO-001", GuardianCategory.SUDO),
            _finding("SUDO-002", GuardianCategory.SUDO, severity=Severity.CRITICAL),
            _finding("SUDO-003", GuardianCategory.SUDO),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 3

    def test_compare_returns_rules_for_ubuntu(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0
        for item in items:
            assert item.category == "sudo"

    def test_compare_marks_finding_present_as_not_matching(self):
        finding = _finding("SUDO-003", GuardianCategory.SUDO)
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        nopasswd_item = next((i for i in items if i.rule == "nopasswd_rules"), None)
        assert nopasswd_item is not None
        assert nopasswd_item.matches_baseline is False
        assert nopasswd_item.current_value == "violation detected"

    def test_compare_marks_no_finding_as_matching(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        for item in items:
            assert item.matches_baseline is True

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []


# ── CronAnalyzer ─────────────────────────────────────────────────────────────


class TestCronAnalyzer:
    def setup_method(self):
        self.analyzer = CronAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.CRON

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_baseline_severity(self):
        finding = _finding("CRON-002", GuardianCategory.CRON, severity=Severity.HIGH)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1
        # Ubuntu baseline marks world_writable_cron_files as CRITICAL
        assert result[0].severity == Severity.CRITICAL

    def test_analyze_returns_all_findings(self):
        findings = [
            _finding("CRON-001", GuardianCategory.CRON),
            _finding("CRON-002", GuardianCategory.CRON),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 2

    def test_analyze_keeps_findings_for_unknown_distro(self):
        finding = _finding("CRON-002", GuardianCategory.CRON)
        result = self.analyzer.analyze([finding], "windows", None)
        assert len(result) == 1

    def test_compare_returns_rules_for_ubuntu(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0
        for item in items:
            assert item.category == "cron"

    def test_compare_marks_finding_as_violation(self):
        finding = _finding("CRON-002", GuardianCategory.CRON)
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        ww_item = next((i for i in items if i.rule == "world_writable_cron_files"), None)
        assert ww_item is not None
        assert ww_item.matches_baseline is False

    def test_compare_clean_is_all_matching(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        for item in items:
            assert item.matches_baseline is True

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []


# ── SecretAnalyzer ───────────────────────────────────────────────────────────


class TestSecretAnalyzer:
    def setup_method(self):
        self.analyzer = SecretAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.SECRET

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_baseline_severity(self):
        finding = _finding("SECRET-001", GuardianCategory.SECRET, severity=Severity.HIGH)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1
        # Ubuntu baseline marks ssh_private_keys as CRITICAL
        assert result[0].severity == Severity.CRITICAL

    def test_analyze_returns_all_findings(self):
        findings = [
            _finding("SECRET-001", GuardianCategory.SECRET),
            _finding("SECRET-002", GuardianCategory.SECRET),
            _finding("SECRET-003", GuardianCategory.SECRET),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 3

    def test_analyze_keeps_findings_for_unknown_distro(self):
        finding = _finding("SECRET-001", GuardianCategory.SECRET)
        result = self.analyzer.analyze([finding], "windows", None)
        assert len(result) == 1

    def test_compare_returns_rules_for_ubuntu(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0
        for item in items:
            assert item.category == "secret"

    def test_compare_marks_finding_as_violation(self):
        finding = _finding("SECRET-001", GuardianCategory.SECRET)
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        ssh_item = next((i for i in items if i.rule == "ssh_private_keys"), None)
        assert ssh_item is not None
        assert ssh_item.matches_baseline is False
        assert ssh_item.current_value == "secret detected"

    def test_compare_clean_is_all_matching(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        for item in items:
            assert item.matches_baseline is True

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []


# ── Baseline loader — 3B rules ───────────────────────────────────────────────


class TestBaselineLoader3B:
    def test_ubuntu_sudo_rules_loaded(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "sudo")
        assert "nopasswd_rules" in rules
        assert "all_all_rules" in rules
        assert "dangerous_commands" in rules

    def test_ubuntu_cron_rules_loaded(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "cron")
        assert "world_writable_cron_files" in rules
        assert "world_writable_cron_scripts" in rules
        assert "cron_directory_permissions" in rules

    def test_ubuntu_secret_rules_loaded(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "secret")
        assert "ssh_private_keys" in rules
        assert "env_file_secrets" in rules
        assert "plaintext_credentials" in rules

    def test_all_distros_have_sudo_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "sudo")
            assert len(rules) > 0, f"No sudo rules for {distro}"

    def test_all_distros_have_cron_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "cron")
            assert len(rules) > 0, f"No cron rules for {distro}"

    def test_all_distros_have_secret_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "secret")
            assert len(rules) > 0, f"No secret rules for {distro}"
