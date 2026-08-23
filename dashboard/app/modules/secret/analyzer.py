"""Secret Guardian — dashboard-side analyzer."""

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
    "SECRET-001": "ssh_private_keys",
    "SECRET-002": "env_file_secrets",
    "SECRET-003": "plaintext_credentials",
}


class SecretAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Secret Guardian findings."""

    category = GuardianCategory.SECRET

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        rules = get_baseline_rules(distro, "secret")
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
        rules = get_baseline_rules(distro, "secret")
        if not rules:
            return []

        found_rule_names: set[str] = set()
        for finding in findings:
            rule_name = _CHECK_TO_RULE.get(finding.check_id)
            if rule_name:
                found_rule_names.add(rule_name)

        items: list[BaselineComparisonItem] = []
        for rule_name, rule in rules.items():
            expected = str(rule.get("expected", "no secrets"))
            current = "secret detected" if rule_name in found_rule_names else None
            items.append(
                BaselineComparisonItem(
                    category="secret",
                    rule=rule_name,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=rule_name not in found_rule_names,
                )
            )
        return items
