"""Firewall Guardian — dashboard-side analyzer."""

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
    "FIREWALL-001": "no_firewall_active",
    "FIREWALL-002": "default_input_policy",
    "FIREWALL-003": "default_forward_policy",
    "FIREWALL-004": "ssh_exposure",
    "FIREWALL-005": "dangerous_ports_open",
    "FIREWALL-006": "ufw_inactive",
    "FIREWALL-007": "firewalld_inactive",
}


class FirewallAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Firewall Guardian findings."""

    category = GuardianCategory.FIREWALL

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        rules = get_baseline_rules(distro, "firewall")
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
        rules = get_baseline_rules(distro, "firewall")
        if not rules:
            return []

        found_rules: set[str] = set()
        for finding in findings:
            rule_name = _CHECK_TO_RULE.get(finding.check_id)
            if rule_name:
                found_rules.add(rule_name)

        items: list[BaselineComparisonItem] = []
        for rule_name, rule in rules.items():
            expected = str(rule.get("expected", "secure"))
            current = "violation detected" if rule_name in found_rules else None
            items.append(
                BaselineComparisonItem(
                    category="firewall",
                    rule=rule_name,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=rule_name not in found_rules,
                )
            )
        return items
