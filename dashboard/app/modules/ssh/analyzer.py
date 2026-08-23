"""SSH Guardian — dashboard-side analyzer."""

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

# Maps check_id to the sshd_config directive name for baseline lookup
_CHECK_TO_DIRECTIVE: dict[str, str] = {
    "SSH-001": "PermitRootLogin",
    "SSH-002": "PasswordAuthentication",
    "SSH-003": "PermitEmptyPasswords",
    "SSH-004": "PubkeyAuthentication",
    "SSH-005": "Ciphers",
    "SSH-006": "MACs",
    "SSH-007": "Protocol",
    "SSH-008": "AllowUsers",  # treated specially
}


class SSHAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for SSH Guardian findings."""

    category = GuardianCategory.SSH

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        """Adjust SSH finding severities based on the distro baseline."""
        rules = get_baseline_rules(distro, "ssh")
        if not rules:
            return findings

        adjusted: list[FindingRecord] = []
        for finding in findings:
            directive = _CHECK_TO_DIRECTIVE.get(finding.check_id)
            if directive and directive in rules:
                rule = rules[directive]
                sev_str = str(rule.get("severity", "")).lower()
                if sev_str in _SEVERITY_MAP:
                    finding = finding.model_copy(update={"severity": _SEVERITY_MAP[sev_str]})
                # Suppress if current matches baseline expectation
                expected = str(rule.get("expected", ""))
                if finding.current_value and finding.current_value == expected:
                    continue
            adjusted.append(finding)
        return adjusted

    def compare(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[BaselineComparisonItem]:
        """Return current-vs-expected comparison for each SSH rule."""
        rules = get_baseline_rules(distro, "ssh")
        if not rules:
            return []

        # Build lookup: directive -> current_value from findings
        current_values: dict[str, str | None] = {}
        for finding in findings:
            directive = _CHECK_TO_DIRECTIVE.get(finding.check_id)
            if directive:
                current_values[directive] = finding.current_value

        items: list[BaselineComparisonItem] = []
        for directive, rule in rules.items():
            expected = str(rule.get("expected", ""))
            current = current_values.get(directive)
            items.append(
                BaselineComparisonItem(
                    category="ssh",
                    rule=directive,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=(current is None or current == expected),
                )
            )
        return items
