"""Tests for Docker, Firewall, and Kernel dashboard-side analyzers."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard_contracts import FindingStatus, GuardianCategory, Severity

from app.modules.docker.analyzer import DockerAnalyzer
from app.modules.firewall.analyzer import FirewallAnalyzer
from app.modules.kernel.analyzer import KernelAnalyzer
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


# ── DockerAnalyzer ───────────────────────────────────────────────────────────


class TestDockerAnalyzer:
    def setup_method(self):
        self.analyzer = DockerAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.DOCKER

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_baseline_severity(self):
        finding = _finding("DOCKER-006", GuardianCategory.DOCKER, severity=Severity.HIGH)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_analyze_returns_all_findings(self):
        findings = [
            _finding("DOCKER-001", GuardianCategory.DOCKER),
            _finding("DOCKER-006", GuardianCategory.DOCKER),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 2

    def test_analyze_unknown_distro(self):
        finding = _finding("DOCKER-006", GuardianCategory.DOCKER)
        result = self.analyzer.analyze([finding], "windows", None)
        assert len(result) == 1

    def test_compare_returns_rules(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) == 13  # 13 docker rules
        for item in items:
            assert item.category == "docker"

    def test_compare_marks_violation(self):
        finding = _finding("DOCKER-006", GuardianCategory.DOCKER)
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        priv_item = next((i for i in items if i.rule == "privileged_containers"), None)
        assert priv_item is not None
        assert priv_item.matches_baseline is False

    def test_compare_clean_all_matching(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert all(i.matches_baseline for i in items)

    def test_compare_empty_for_unknown_distro(self):
        assert self.analyzer.compare([], "windows", None) == []


# ── FirewallAnalyzer ─────────────────────────────────────────────────────────


class TestFirewallAnalyzer:
    def setup_method(self):
        self.analyzer = FirewallAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.FIREWALL

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_severity(self):
        finding = _finding("FIREWALL-001", GuardianCategory.FIREWALL, severity=Severity.HIGH)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert result[0].severity == Severity.CRITICAL

    def test_analyze_returns_all_findings(self):
        findings = [
            _finding("FIREWALL-002", GuardianCategory.FIREWALL),
            _finding("FIREWALL-004", GuardianCategory.FIREWALL),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 2

    def test_compare_returns_seven_rules(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) == 7
        for item in items:
            assert item.category == "firewall"

    def test_compare_marks_violation(self):
        finding = _finding("FIREWALL-001", GuardianCategory.FIREWALL)
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        item = next((i for i in items if i.rule == "no_firewall_active"), None)
        assert item is not None
        assert item.matches_baseline is False

    def test_compare_empty_for_unknown_distro(self):
        assert self.analyzer.compare([], "windows", None) == []


# ── KernelAnalyzer ───────────────────────────────────────────────────────────


class TestKernelAnalyzer:
    def setup_method(self):
        self.analyzer = KernelAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.KERNEL

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_applies_severity(self):
        finding = _finding("KERNEL-001", GuardianCategory.KERNEL, severity=Severity.MEDIUM)
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert result[0].severity == Severity.HIGH

    def test_analyze_returns_all_findings(self):
        findings = [
            _finding("KERNEL-001", GuardianCategory.KERNEL),
            _finding("KERNEL-007", GuardianCategory.KERNEL),
        ]
        result = self.analyzer.analyze(findings, "ubuntu", "24.04")
        assert len(result) == 2

    def test_compare_returns_thirteen_rules(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) == 13  # 12 sysctl + 1 kernel_version
        for item in items:
            assert item.category == "kernel"

    def test_compare_marks_current_value(self):
        finding = _finding(
            "KERNEL-001", GuardianCategory.KERNEL, current_value="0", expected_value="2"
        )
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        item = next((i for i in items if i.rule == "kernel.randomize_va_space"), None)
        assert item is not None
        assert item.current_value == "0"
        assert item.matches_baseline is False

    def test_compare_no_finding_treated_as_matching(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert all(i.matches_baseline for i in items)

    def test_compare_empty_for_unknown_distro(self):
        assert self.analyzer.compare([], "windows", None) == []


# ── Baseline loader — 3C rules ───────────────────────────────────────────────


class TestBaselineLoader3C:
    def test_ubuntu_docker_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "docker")
        assert "privileged_containers" in rules
        assert "dangerous_capabilities" in rules
        assert "root_containers" in rules

    def test_ubuntu_firewall_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "firewall")
        assert "no_firewall_active" in rules
        assert "default_input_policy" in rules

    def test_ubuntu_kernel_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        rules = get_baseline_rules("ubuntu", "kernel")
        assert "kernel.randomize_va_space" in rules
        assert "kernel_version" in rules

    def test_all_distros_have_docker_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "docker")
            assert len(rules) == 13, f"docker rules mismatch for {distro}"

    def test_all_distros_have_firewall_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "firewall")
            assert len(rules) == 7, f"firewall rules mismatch for {distro}"

    def test_all_distros_have_kernel_rules(self):
        from app.modules.baseline_loader import get_baseline_rules

        for distro in ("ubuntu", "debian", "fedora", "rocky", "centos"):
            rules = get_baseline_rules(distro, "kernel")
            assert len(rules) == 13, f"kernel rules mismatch for {distro}"

    def test_unknown_distro_file_returns_empty(self):
        from app.modules.baseline_loader import get_baseline_rules

        assert get_baseline_rules("solaris", "kernel") == {}

    def test_malformed_yaml_returns_empty(self, tmp_path, monkeypatch):
        from app.modules import baseline_loader

        bad_file = tmp_path / "badyaml.yaml"
        bad_file.write_text("key: [unterminated\n  - broken")
        monkeypatch.setattr(baseline_loader, "_BASELINES_DIR", tmp_path)
        baseline_loader._load_baseline_yaml.cache_clear()

        result = baseline_loader.get_baseline_rules("badyaml", "kernel")
        assert result == {}
        baseline_loader._load_baseline_yaml.cache_clear()
