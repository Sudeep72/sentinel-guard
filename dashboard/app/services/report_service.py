"""Report Engine (Phase 19).

Generates reports in four formats — Executive, Technical, Markdown,
JSON — from real, currently-available data: server info, the
requested (or latest) scan, its findings, its automatically-computed
security score (Phase 18), and its baseline comparison (Phase 17).

Every report includes, per the Phase 19 spec:
    server information, security score, category scores, findings
    grouped by category, a severity summary, recommendations, baseline
    comparison, metadata, and a generation timestamp.

Executive vs. Technical is a level-of-detail distinction, not a
different data source: Executive omits attack-scenario/current-value/
expected-value detail and full baseline comparison to stay skimmable
for a non-technical audience; Technical (and Markdown, its synonym in
v1) includes everything.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sentinelguard_contracts import Report, ReportFormat, ServerInfo, Severity
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.scan import Scan
from app.schemas.baselines import BaselineComparisonResponse
from app.schemas.findings import FindingRecord
from app.schemas.scores import SecurityScoreResponse
from app.services.baseline_service import compare_to_baseline
from app.services.finding_service import list_findings
from app.services.scan_service import get_latest_scan, get_scan
from app.services.score_service import get_security_score
from app.services.server_service import get_server

# Fixed display order so reports are stable/reproducible across runs.
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def generate_report(
    db: Session, server_id: str, format: ReportFormat, scan_id: str | None = None
) -> Report:
    """Generate a report for a server's scan in the requested format.

    Raises:
        NotFoundError: If the server doesn't exist, or no scan_id was
            given and the server has no scans yet.
    """
    server = get_server(db, server_id)

    if scan_id is None:
        latest = get_latest_scan(db, server_id)
        if latest is None:
            raise NotFoundError(f"Server {server_id!r} has no scans yet")
        scan = latest
    else:
        scan = get_scan(db, scan_id)

    findings = list_findings(db, server_id=server_id, scan_id=scan.id)
    score_response = get_security_score(db, server_id=server_id, scan_id=scan.id)
    baseline_response = compare_to_baseline(db, server_id=server_id)
    severity_summary = _compute_severity_summary(findings)
    findings_by_category = _group_findings_by_category(findings)
    generated_at = datetime.now(UTC)

    if format == ReportFormat.JSON:
        content = _render_json(
            server,
            scan,
            findings_by_category,
            score_response,
            baseline_response,
            severity_summary,
            generated_at,
        )
    elif format in (ReportFormat.MARKDOWN, ReportFormat.TECHNICAL):
        content = _render_markdown(
            server,
            scan,
            findings_by_category,
            score_response,
            baseline_response,
            severity_summary,
            generated_at,
            technical=True,
        )
    else:  # ReportFormat.EXECUTIVE
        content = _render_markdown(
            server,
            scan,
            findings_by_category,
            score_response,
            baseline_response,
            severity_summary,
            generated_at,
            technical=False,
        )

    return Report(
        server_id=server_id,
        scan_id=scan.id,
        format=format,
        generated_at=generated_at,
        content=content,
    )


# ---------------------------------------------------------------------------
# Shared computation — used by every format
# ---------------------------------------------------------------------------


def _compute_severity_summary(findings: list[FindingRecord]) -> dict[str, int]:
    """Count findings per severity, with every severity present (even at 0)
    so downstream renderers (and the frontend) never have to guess a
    missing key means zero vs. "not computed"."""
    summary: dict[str, int] = {s.value: 0 for s in _SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity.value] += 1
    return summary


def _group_findings_by_category(
    findings: list[FindingRecord],
) -> dict[str, list[FindingRecord]]:
    """Group findings by Guardian category, in a fixed category order
    matching CATEGORY_WEIGHTS' significance ordering, so reports render
    the same section order every time regardless of scan order."""
    from app.services.scoring_service import CATEGORY_WEIGHTS

    grouped: dict[str, list[FindingRecord]] = {cat.value: [] for cat in CATEGORY_WEIGHTS}
    for finding in findings:
        grouped[finding.module.value].append(finding)
    return grouped


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def _render_json(
    server: ServerInfo,
    scan: Scan,
    findings_by_category: dict[str, list[FindingRecord]],
    score_response: SecurityScoreResponse,
    baseline_response: BaselineComparisonResponse,
    severity_summary: dict[str, int],
    generated_at: datetime,
) -> str:
    payload = {
        "metadata": {
            "report_type": "sentinelguard_security_report",
            "generated_at": generated_at.isoformat(),
            "sentinelguard_baseline_version": score_response.baseline_version,
        },
        "server": {
            "id": server.id,
            "hostname": server.hostname,
            "distro": server.distro.value,
            "distro_version": server.distro_version,
        },
        "scan": {
            "id": scan.id,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat(),
            "status": scan.status,
        },
        "score": json.loads(score_response.model_dump_json()),
        "severity_summary": severity_summary,
        "findings_by_category": {
            category: [json.loads(f.model_dump_json()) for f in findings]
            for category, findings in findings_by_category.items()
        },
        "baseline_comparison": json.loads(baseline_response.model_dump_json()),
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Markdown / Executive / Technical renderer
# ---------------------------------------------------------------------------


def _render_markdown(
    server: ServerInfo,
    scan: Scan,
    findings_by_category: dict[str, list[FindingRecord]],
    score_response: SecurityScoreResponse,
    baseline_response: BaselineComparisonResponse,
    severity_summary: dict[str, int],
    generated_at: datetime,
    *,
    technical: bool,
) -> str:
    lines: list[str] = []
    report_kind = "Technical Report" if technical else "Executive Report"

    lines.append(f"# SentinelGuard {report_kind} — {server.hostname}")
    lines.append("")
    lines.append(f"_Generated {generated_at.isoformat()}_")
    lines.append("")

    lines.append("## Server Information")
    lines.append(
        f"- **Hostname:** {server.hostname} ({server.distro.value} {server.distro_version or ''})"
    )
    lines.append(f"- **Server ID:** {server.id}")
    lines.append(f"- **Scan:** {scan.id} ({scan.status})")
    scan_window = f"{scan.started_at.isoformat()} → {scan.completed_at.isoformat()}"
    lines.append(f"- **Scan window:** {scan_window}")
    lines.append("")

    lines.extend(_render_score_section(score_response))
    lines.extend(_render_severity_summary_section(severity_summary))
    lines.extend(_render_findings_sections(findings_by_category, technical=technical))

    if technical:
        lines.extend(_render_baseline_section(baseline_response))

    return "\n".join(lines)


def _render_score_section(score_response: SecurityScoreResponse) -> list[str]:
    lines = ["## Security Score"]
    if score_response.available and score_response.score is not None:
        lines.append(f"**Overall score: {score_response.score.overall_score:.1f}/100**")
        if score_response.total_checks is not None:
            lines.append(
                f"Checks: {score_response.passed_checks}/{score_response.total_checks} passed"
            )
        if score_response.baseline_version:
            lines.append(f"Baseline version: {score_response.baseline_version}")
        lines.append("")
        lines.append("### Category Scores")
        for cat in score_response.score.category_scores:
            lines.append(f"- {cat.category.value}: {cat.score:.1f}/100 (weight {cat.weight:.0%})")
    else:
        lines.append(f"_{score_response.message}_")
    lines.append("")
    return lines


def _render_severity_summary_section(severity_summary: dict[str, int]) -> list[str]:
    lines = ["## Severity Summary"]
    for severity in _SEVERITY_ORDER:
        lines.append(f"- {severity.value.capitalize()}: {severity_summary[severity.value]}")
    lines.append("")
    return lines


def _render_findings_sections(
    findings_by_category: dict[str, list[FindingRecord]], *, technical: bool
) -> list[str]:
    lines: list[str] = []
    total_findings = sum(len(f) for f in findings_by_category.values())
    lines.append(f"## Findings ({total_findings})")

    if total_findings == 0:
        lines.append("_No findings recorded for this scan._")
        lines.append("")
        return lines

    for category, findings in findings_by_category.items():
        if not findings:
            continue
        lines.append(f"### {category} ({len(findings)})")
        for finding in findings:
            lines.append(f"#### [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"- **Check:** {finding.check_id}")
            lines.append(f"- **Description:** {finding.description}")
            if technical:
                lines.append(f"- **Why it matters:** {finding.why_it_matters}")
                lines.append(f"- **Attack scenario:** {finding.attack_scenario}")
                if finding.current_value is not None:
                    lines.append(f"- **Current value:** {finding.current_value}")
                if finding.expected_value is not None:
                    lines.append(f"- **Expected value:** {finding.expected_value}")
            lines.append(f"- **Recommendation:** {finding.recommendation}")
            lines.append("")

    return lines


def _render_baseline_section(baseline_response: BaselineComparisonResponse) -> list[str]:
    lines = ["## Baseline Comparison"]
    if not baseline_response.available:
        lines.append(f"_{baseline_response.message}_")
        lines.append("")
        return lines

    lines.append(f"Distro baseline: {baseline_response.distro}")
    lines.append("")
    mismatches = [c for c in baseline_response.comparisons if not c.matches_baseline]
    if mismatches:
        lines.append(f"### Deviations from baseline ({len(mismatches)})")
        for item in mismatches:
            lines.append(
                f"- **{item.category}/{item.rule}**: current=`{item.current_value}`, "
                f"expected=`{item.expected_value}`"
            )
    else:
        lines.append("_No deviations from baseline detected._")
    lines.append("")
    return lines
