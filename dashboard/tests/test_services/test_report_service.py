import json
from datetime import UTC, datetime, timedelta

import pytest
from sentinelguard_contracts import (
    Distro,
    Finding,
    GuardianCategory,
    GuardianResult,
    GuardianRunStatus,
    ReportFormat,
    ScanPayload,
    ScanStatus,
    ServerRegistration,
    Severity,
)

from app.core.exceptions import NotFoundError
from app.services.report_service import generate_report
from app.services.scan_service import ingest_scan
from app.services.server_service import get_server_orm_or_none, register_server


def _server(db_session, hostname="web01"):
    registration = ServerRegistration(
        hostname=hostname, distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _finding(check_id="PERM-001", module=GuardianCategory.PERMISSION, severity=Severity.CRITICAL):
    return Finding(
        check_id=check_id,
        module=module,
        title="/etc/shadow is world-readable",
        severity=severity,
        description="/etc/shadow has mode 644.",
        why_it_matters="Password hashes become readable.",
        attack_scenario="Offline cracking becomes possible.",
        recommendation="chmod 600 /etc/shadow",
        current_value="644",
        expected_value="600",
    )


def _scan_with_findings(db_session, server, findings):
    now = datetime.now(UTC)
    payload = ScanPayload(
        server_id=server.id,
        hostname=server.hostname,
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=now - timedelta(seconds=5),
        completed_at=now,
        status=ScanStatus.COMPLETED,
        guardian_results=(
            [
                GuardianResult(
                    module=GuardianCategory.PERMISSION,
                    status=GuardianRunStatus.OK,
                    findings=findings,
                    collected_at=now,
                )
            ]
            if findings
            else []
        ),
    )
    return ingest_scan(db_session, server, payload)


def test_generate_report_server_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        generate_report(db_session, server_id="nonexistent-id", format=ReportFormat.JSON)


def test_generate_report_no_scans_raises(db_session):
    server = _server(db_session)
    with pytest.raises(NotFoundError):
        generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)


# ── JSON format ──────────────────────────────────────────────────────────────


def test_generate_report_json_format_is_valid_json(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)

    assert report.format == ReportFormat.JSON
    parsed = json.loads(report.content)
    assert parsed["server"]["hostname"] == "web01"
    assert len(parsed["findings_by_category"]["permission"]) == 1


def test_generate_report_json_includes_all_required_sections(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)
    parsed = json.loads(report.content)

    assert "metadata" in parsed
    assert "server" in parsed
    assert "scan" in parsed
    assert "score" in parsed
    assert "severity_summary" in parsed
    assert "findings_by_category" in parsed
    assert "baseline_comparison" in parsed


def test_generate_report_json_severity_summary_counts_correctly(db_session):
    server = _server(db_session)
    _scan_with_findings(
        db_session,
        server,
        [
            _finding("PERM-001", severity=Severity.CRITICAL),
            _finding("PERM-002", severity=Severity.CRITICAL),
            _finding("PERM-003", severity=Severity.LOW),
        ],
    )

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)
    parsed = json.loads(report.content)

    assert parsed["severity_summary"]["critical"] == 2
    assert parsed["severity_summary"]["low"] == 1
    assert parsed["severity_summary"]["high"] == 0
    assert parsed["severity_summary"]["medium"] == 0
    assert parsed["severity_summary"]["info"] == 0


def test_generate_report_json_metadata_has_timestamp_and_baseline_version(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)
    parsed = json.loads(report.content)

    assert parsed["metadata"]["generated_at"]
    assert parsed["metadata"]["sentinelguard_baseline_version"] == "1.0.0"


def test_generate_report_json_findings_grouped_by_category(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding(module=GuardianCategory.PERMISSION)])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.JSON)
    parsed = json.loads(report.content)

    # All nine categories present as keys, even with no findings
    assert len(parsed["findings_by_category"]) == 9
    assert len(parsed["findings_by_category"]["permission"]) == 1
    assert len(parsed["findings_by_category"]["ssh"]) == 0


# ── Markdown / Technical / Executive ────────────────────────────────────────


def test_generate_report_markdown_format_contains_finding(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)

    assert report.format == ReportFormat.MARKDOWN
    assert "/etc/shadow is world-readable" in report.content
    assert "chmod 600 /etc/shadow" in report.content
    assert "# SentinelGuard Technical Report" in report.content


def test_generate_report_technical_includes_attack_scenario(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.TECHNICAL)
    assert "Attack scenario" in report.content
    assert "# SentinelGuard Technical Report" in report.content


def test_generate_report_technical_includes_baseline_section(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.TECHNICAL)
    assert "## Baseline Comparison" in report.content


def test_generate_report_executive_omits_attack_scenario(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.EXECUTIVE)
    assert "Attack scenario" not in report.content
    assert "# SentinelGuard Executive Report" in report.content
    # still shows the finding itself at a high level
    assert "/etc/shadow is world-readable" in report.content


def test_generate_report_executive_omits_baseline_section(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.EXECUTIVE)
    assert "## Baseline Comparison" not in report.content


def test_generate_report_includes_severity_summary_section(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding(severity=Severity.HIGH)])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)
    assert "## Severity Summary" in report.content
    assert "High: 1" in report.content


def test_generate_report_includes_category_scores_section(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)
    assert "### Category Scores" in report.content


def test_generate_report_includes_server_information_section(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)
    assert "## Server Information" in report.content
    assert server.id in report.content


def test_generate_report_handles_zero_findings_gracefully(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)
    assert "No findings recorded" in report.content


def test_generate_report_groups_findings_by_category_headers(db_session):
    server = _server(db_session)
    _scan_with_findings(db_session, server, [_finding(module=GuardianCategory.PERMISSION)])

    report = generate_report(db_session, server_id=server.id, format=ReportFormat.MARKDOWN)
    assert "### permission (1)" in report.content


def test_generate_report_uses_specific_scan_id(db_session):
    server = _server(db_session)
    scan1 = _scan_with_findings(db_session, server, [_finding()])

    report = generate_report(
        db_session, server_id=server.id, format=ReportFormat.JSON, scan_id=scan1.id
    )
    assert report.scan_id == scan1.id
