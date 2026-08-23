"""Ownership Guardian — dashboard-side analyzer."""

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


class OwnershipAnalyzer(BaseAnalyzer):
    """Dashboard-side analyzer for Ownership Guardian findings."""

    category = GuardianCategory.OWNERSHIP

    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        """Adjust finding severities against the distro ownership baseline."""
        rules = get_baseline_rules(distro, "ownership")
        if not rules:
            return findings

        adjusted: list[FindingRecord] = []
        for finding in findings:
            if finding.check_id == "OWN-001":
                path = self._extract_path_own001(finding)
                if path and path in rules:
                    rule = rules[path]
                    expected_uid = rule.get("expected_uid")
                    expected_gid = rule.get("expected_gid")
                    expected_str = (
                        f"uid={expected_uid if expected_uid is not None else 'any'}, "
                        f"gid={expected_gid if expected_gid is not None else 'any'}"
                    )
                    # Check if current matches baseline
                    if finding.current_value == expected_str:
                        continue  # suppress — baseline-correct
                    sev_str = str(rule.get("severity", "")).lower()
                    if sev_str in _SEVERITY_MAP:
                        finding = finding.model_copy(
                            update={
                                "severity": _SEVERITY_MAP[sev_str],
                                "expected_value": expected_str,
                            }
                        )
            adjusted.append(finding)
        return adjusted

    def compare(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[BaselineComparisonItem]:
        """Return current-vs-expected ownership comparison for each rule."""
        rules = get_baseline_rules(distro, "ownership")
        if not rules:
            return []

        current_values: dict[str, str | None] = {}
        for finding in findings:
            if finding.check_id == "OWN-001":
                path = self._extract_path_own001(finding)
                if path:
                    current_values[path] = finding.current_value

        items: list[BaselineComparisonItem] = []
        for path, rule in rules.items():
            expected_uid = rule.get("expected_uid")
            expected_gid = rule.get("expected_gid")
            expected = (
                f"uid={expected_uid if expected_uid is not None else 'any'}, "
                f"gid={expected_gid if expected_gid is not None else 'any'}"
            )
            current = current_values.get(path)
            items.append(
                BaselineComparisonItem(
                    category="ownership",
                    rule=path,
                    current_value=current,
                    expected_value=expected,
                    matches_baseline=(current is None or current == expected),
                )
            )
        return items

    def _extract_path_own001(self, finding: FindingRecord) -> str | None:
        prefix = "Incorrect ownership on "
        if finding.title.startswith(prefix):
            return finding.title[len(prefix) :]
        return None
