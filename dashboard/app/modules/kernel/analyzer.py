"""Kernel Guardian — dashboard-side analyzer."""

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

# Maps check_id to baseline rule key (which is the sysctl key for most checks)
_CHECK_TO_RULE: dict[str, str] = {
    "KERNEL-001": "kernel.randomize_va_space",
    "KERNEL-002": "kernel.yama.ptrace_scope",
    "KERNEL-003": "fs.suid_dumpable",
    "KERNEL-004": "kernel.dmesg_restrict",
    "KERNEL-005": "kernel.kexec_load_disabled",
    "KERNEL-006": "net.ipv4.ip_forward",
    "KERNEL-007": "net.ipv4.tcp_syncookies",
    "KERNEL-008": "net.ipv4.conf.all.accept_redirects",
    "KERNEL-009": "net.ipv4.conf.all.accept_source_route",
    "KERNEL-010": "net.ipv6.conf.all.accept_ra",
    "KERNEL-011": "kernel.kptr_restrict",
    "KERNEL-012": "kernel.unprivileged_bpf_disabled",
    "KERNEL-013": "kernel_version",
}


class KernelAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Kernel Guardian findings."""

    category = GuardianCategory.KERNEL

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        rules = get_baseline_rules(distro, "kernel")
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
        rules = get_baseline_rules(distro, "kernel")
        if not rules:
            return []

        # Map rule_name -> current_value from findings
        found_values: dict[str, str | None] = {}
        for finding in findings:
            rule_name = _CHECK_TO_RULE.get(finding.check_id)
            if rule_name:
                found_values[rule_name] = finding.current_value

        items: list[BaselineComparisonItem] = []
        for rule_name, rule in rules.items():
            expected = str(rule.get("expected", ""))
            current = found_values.get(rule_name)
            matches = current is None or current == expected
            items.append(
                BaselineComparisonItem(
                    category="kernel",
                    rule=rule_name,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=matches,
                )
            )
        return items
