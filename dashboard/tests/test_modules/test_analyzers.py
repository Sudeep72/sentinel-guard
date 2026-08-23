"""Tests for Permission, Ownership, and SSH dashboard-side analyzers."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard_contracts import FindingStatus, GuardianCategory, Severity

from app.modules.ownership.analyzer import OwnershipAnalyzer
from app.modules.permission.analyzer import PermissionAnalyzer
from app.modules.ssh.analyzer import SSHAnalyzer
from app.schemas.findings import FindingRecord


def _finding(
    check_id: str,
    module: GuardianCategory,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    current_value: str | None = None,
    expected_value: str | None = None,
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
        recommendation="recommendation",
        current_value=current_value,
        expected_value=expected_value,
        status=FindingStatus.OPEN,
        created_at=datetime.now(UTC),
    )


# ── PermissionAnalyzer ───────────────────────────────────────────────────────


class TestPermissionAnalyzer:
    def setup_method(self):
        self.analyzer = PermissionAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.PERMISSION

    def test_analyze_empty_findings(self):
        result = self.analyzer.analyze([], "ubuntu", "24.04")
        assert result == []

    def test_analyze_suppresses_baseline_correct_finding(self):
        """If current == expected for ubuntu baseline, suppress it."""
        finding = _finding(
            check_id="PERM-001",
            module=GuardianCategory.PERMISSION,
            title="Insecure permissions on /etc/shadow",
            current_value="0o0640",  # matches ubuntu baseline
            expected_value="0o0640",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        # Current == expected means baseline-correct — should be suppressed
        assert len(result) == 0

    def test_analyze_keeps_finding_when_wrong(self):
        finding = _finding(
            check_id="PERM-001",
            module=GuardianCategory.PERMISSION,
            title="Insecure permissions on /etc/shadow",
            current_value="0o0644",
            expected_value="0o0640",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1

    def test_analyze_no_rules_for_unknown_distro(self):
        finding = _finding(
            "PERM-001", GuardianCategory.PERMISSION, title="Insecure permissions on /etc/shadow"
        )
        result = self.analyzer.analyze([finding], "windows", None)
        assert len(result) == 1  # no baseline, no change

    def test_compare_produces_items_for_ubuntu(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0
        for item in items:
            assert item.category == "permission"
            assert item.expected_value is not None

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []

    def test_compare_marks_no_finding_as_matching(self):
        """When there's no finding for a rule, it's treated as baseline-matching (not observed)."""
        items = self.analyzer.compare([], "ubuntu", "24.04")
        for item in items:
            assert item.matches_baseline is True

    def test_compare_marks_wrong_value_as_not_matching(self):
        finding = _finding(
            check_id="PERM-001",
            module=GuardianCategory.PERMISSION,
            title="Insecure permissions on /etc/shadow",
            current_value="0o0644",
            expected_value="0o0640",
        )
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        shadow_item = next((i for i in items if i.rule == "/etc/shadow"), None)
        assert shadow_item is not None
        assert shadow_item.matches_baseline is False


# ── OwnershipAnalyzer ────────────────────────────────────────────────────────


class TestOwnershipAnalyzer:
    def setup_method(self):
        self.analyzer = OwnershipAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.OWNERSHIP

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_suppresses_baseline_correct_ownership(self):
        finding = _finding(
            check_id="OWN-001",
            module=GuardianCategory.OWNERSHIP,
            title="Incorrect ownership on /etc/shadow",
            current_value="uid=0, gid=42",
            expected_value="uid=0, gid=42",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 0

    def test_analyze_keeps_wrong_ownership(self):
        finding = _finding(
            check_id="OWN-001",
            module=GuardianCategory.OWNERSHIP,
            title="Incorrect ownership on /etc/shadow",
            current_value="uid=1000, gid=1000",
            expected_value="uid=0, gid=42",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1

    def test_compare_produces_items(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []


# ── SSHAnalyzer ──────────────────────────────────────────────────────────────


class TestSSHAnalyzer:
    def setup_method(self):
        self.analyzer = SSHAnalyzer()

    def test_category(self):
        assert self.analyzer.category == GuardianCategory.SSH

    def test_analyze_empty(self):
        assert self.analyzer.analyze([], "ubuntu", "24.04") == []

    def test_analyze_suppresses_when_current_matches_expected(self):
        finding = _finding(
            check_id="SSH-001",
            module=GuardianCategory.SSH,
            title="SSH root login is permitted",
            current_value="no",  # matches baseline expected
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 0

    def test_analyze_keeps_finding_when_wrong(self):
        finding = _finding(
            check_id="SSH-001",
            module=GuardianCategory.SSH,
            title="SSH root login is permitted",
            current_value="yes",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1

    def test_analyze_applies_baseline_severity(self):
        finding = _finding(
            check_id="SSH-003",
            module=GuardianCategory.SSH,
            title="SSH empty passwords are permitted",
            severity=Severity.MEDIUM,  # agent assigned medium
            current_value="yes",
        )
        result = self.analyzer.analyze([finding], "ubuntu", "24.04")
        assert len(result) == 1
        # Ubuntu baseline marks SSH-003 as critical
        assert result[0].severity == Severity.CRITICAL

    def test_compare_returns_items_for_ubuntu(self):
        items = self.analyzer.compare([], "ubuntu", "24.04")
        assert len(items) > 0
        for item in items:
            assert item.category == "ssh"

    def test_compare_marks_finding_current_value(self):
        finding = _finding(
            check_id="SSH-001",
            module=GuardianCategory.SSH,
            title="SSH root login is permitted",
            current_value="yes",
        )
        items = self.analyzer.compare([finding], "ubuntu", "24.04")
        root_item = next((i for i in items if i.rule == "PermitRootLogin"), None)
        assert root_item is not None
        assert root_item.current_value == "yes"
        assert root_item.matches_baseline is False

    def test_compare_empty_for_unknown_distro(self):
        items = self.analyzer.compare([], "windows", None)
        assert items == []
