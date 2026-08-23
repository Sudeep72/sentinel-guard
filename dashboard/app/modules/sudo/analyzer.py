"""Sudo Guardian — dashboard-side analyzer."""

from __future__ import annotations

from sentinelguard_contracts import GuardianCategory, Severity

from app.modules.baseline_loader import get_baseline_rules
from app.modules.registry import BaseAnalyzer
from app.schemas.baselines import BaselineComparisonItem
from app.schemas.findings import FindingRecord

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_CHECK_TO_RULE: dict[str, str] = {
    "SUDO-001": "sudoers_permissions",
    "SUDO-002": "writable_sudoers",
    "SUDO-003": "nopasswd_rules",
    "SUDO-004": "all_all_rules",
    "SUDO-005": "dangerous_commands",
}


class SudoAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Sudo Guardian findings."""

    category = GuardianCategory.SUDO

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        """Adjust sudo finding severities based on the distro baseline."""
        rules = get_baseline_rules(distro, "sudo")
        if not rules:
            return findings

        adjusted: list[FindingRecord] = []
        for finding in findings:
            rule_name = _CHECK_TO_RULE.get(finding.check_id)
            if rule_name and rule_name in rules:
                rule = rules[rule_name]
                sev_str = str(rule.get("severity", "")).lower()
                if sev_str in _SEVERITY_MAP:
                    finding = finding.model_copy(update={"severity": _SEVERITY_MAP[sev_str]})
            adjusted.append(finding)
        return adjusted

    def compare(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[BaselineComparisonItem]:
        """Return current-vs-expected comparison for sudo rules."""
        rules = get_baseline_rules(distro, "sudo")
        if not rules:
            return []

        # Map rule name -> finding present
        found_rule_names: set[str] = set()
        for finding in findings:
            rule_name = _CHECK_TO_RULE.get(finding.check_id)
            if rule_name:
                found_rule_names.add(rule_name)

        items: list[BaselineComparisonItem] = []
        for rule_name, rule in rules.items():
            expected = str(rule.get("expected", "secure"))
            current = "violation detected" if rule_name in found_rule_names else None
            items.append(
                BaselineComparisonItem(
                    category="sudo",
                    rule=rule_name,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=rule_name not in found_rule_names,
                )
            )
        return items
