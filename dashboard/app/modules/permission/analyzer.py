"""Permission Guardian — dashboard-side analyzer.

Receives the ``Finding`` objects the agent's ``PermissionGuardian``
collector emitted and compares them against the distro-specific baseline
loaded from ``app/baselines/<distro>.yaml``.  Also generates
``BaselineComparisonItem`` objects for the ``compare_to_baseline``
MCP tool / REST endpoint.
"""

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


class PermissionAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Permission Guardian findings."""

    category = GuardianCategory.PERMISSION

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        """Adjust finding severities based on the distro baseline.

        The agent assigns preliminary severities; the baseline may
        override them (e.g. on RHEL /etc/shadow is mode 0000, not 0640,
        so what looks "wrong" from a generic perspective may be baseline-
        correct on that distro and the finding can be suppressed or
        downgraded).
        """
        rules = get_baseline_rules(distro, "permission")
        if not rules:
            return findings

        adjusted: list[FindingRecord] = []
        for finding in findings:
            # Extract the path from the finding title/description
            path = self._extract_path(finding)
            if path and path in rules:
                rule = rules[path]
                baseline_expected = str(rule.get("expected", ""))
                if finding.expected_value and baseline_expected:
                    # Update expected value from baseline
                    finding = finding.model_copy(update={"expected_value": baseline_expected})
                # If current value matches the baseline expectation,
                # this finding may be a false-positive for this distro.
                if finding.current_value == baseline_expected:
                    continue  # suppress — matches baseline
                # Override severity from baseline if specified
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
        """Return a current-vs-expected comparison for each permission rule."""
        rules = get_baseline_rules(distro, "permission")
        if not rules:
            return []

        # Build lookup: path -> current observed value (from findings)
        current_values: dict[str, str | None] = {}
        for finding in findings:
            path = self._extract_path(finding)
            if path:
                current_values[path] = finding.current_value

        items: list[BaselineComparisonItem] = []
        for path, rule in rules.items():
            expected = str(rule.get("expected", ""))
            current = current_values.get(path)
            items.append(
                BaselineComparisonItem(
                    category="permission",
                    rule=path,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=(current is None or current == expected),
                )
            )
        return items

    def _extract_path(self, finding: FindingRecord) -> str | None:
        """Extract the file path from a permission finding's title."""
        # Titles are "Insecure permissions on /etc/shadow" etc.
        for prefix in (
            "Insecure permissions on ",
            "World-writable file: ",
            "World-readable sensitive file: ",
        ):
            if finding.title.startswith(prefix):
                return finding.title[len(prefix) :]
        return None
