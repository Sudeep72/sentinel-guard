"""Docker Guardian — dashboard-side analyzer."""

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
    "DOCKER-001": "socket_world_writable",
    "DOCKER-002": "socket_group_ownership",
    "DOCKER-003": "tcp_socket_exposure",
    "DOCKER-004": "no_new_privileges",
    "DOCKER-005": "userland_proxy",
    "DOCKER-006": "privileged_containers",
    "DOCKER-007": "host_pid_namespace",
    "DOCKER-008": "host_network_namespace",
    "DOCKER-009": "host_ipc_namespace",
    "DOCKER-010": "dangerous_capabilities",
    "DOCKER-011": "root_containers",
    "DOCKER-012": "dangerous_host_mounts",
    "DOCKER-013": "latest_tag",
}


class DockerAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Docker Guardian findings."""

    category = GuardianCategory.DOCKER

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        rules = get_baseline_rules(distro, "docker")
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
        rules = get_baseline_rules(distro, "docker")
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
                    category="docker",
                    rule=rule_name,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=rule_name not in found_rules,
                )
            )
        return items
