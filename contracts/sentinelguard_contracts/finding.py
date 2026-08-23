"""The Finding model — the atomic unit of the AI Security Copilot output.

Every finding, regardless of which Guardian produced it, carries the
same shape so the dashboard, reports, and MCP tools can treat findings
uniformly: title, severity, description, why it matters, a realistic
attack scenario, and a concrete recommendation.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from sentinelguard_contracts.enums import GuardianCategory, Severity


class Finding(BaseModel):
    """A single security finding produced by a Guardian.

    Attributes:
        check_id: Stable rule identifier (e.g. ``"SSH-001"``), consistent
            across scans so trend tracking and AI references stay stable
            even though the dashboard-side ``Finding`` DB row gets a new
            UUID each scan.
        module: Which Guardian category this finding belongs to.
        title: Short human-readable summary, e.g. "/etc/shadow is world-readable".
        severity: Impact severity, drives the scoring penalty.
        description: What was observed.
        why_it_matters: Plain-language impact explanation.
        attack_scenario: A realistic scenario describing how this could be exploited.
        recommendation: Concrete remediation step(s).
        current_value: The raw observed value (e.g. "644").
        expected_value: The baseline-expected value (e.g. "600"), if applicable.
    """

    model_config = ConfigDict(str_strip_whitespace=True, use_enum_values=False)

    check_id: str = Field(min_length=1, max_length=32)
    module: GuardianCategory
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    description: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)
    attack_scenario: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    current_value: str | None = None
    expected_value: str | None = None
