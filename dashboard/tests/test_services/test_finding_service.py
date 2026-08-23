from datetime import UTC, datetime, timedelta

import pytest
from sentinelguard_contracts import (
    Distro,
    Finding,
    GuardianCategory,
    GuardianResult,
    GuardianRunStatus,
    ScanPayload,
    ScanStatus,
    ServerRegistration,
    Severity,
)

from app.core.exceptions import NotFoundError
from app.services.finding_service import explain_finding, list_findings
from app.services.scan_service import ingest_scan
from app.services.server_service import get_server_orm_or_none, register_server


def _server(db_session, hostname="web01"):
    registration = ServerRegistration(
        hostname=hostname, distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _finding(check_id, module, severity) -> Finding:
    return Finding(
        check_id=check_id,
        module=module,
        title=f"Finding {check_id}",
        severity=severity,
        description="description",
        why_it_matters="why it matters",
        attack_scenario="attack scenario",
        recommendation="recommendation",
    )


def _seed_scan_with_findings(db_session, server, findings):
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
        guardian_results=[
            GuardianResult(
                module=GuardianCategory.PERMISSION,
                status=GuardianRunStatus.OK,
                findings=findings,
                collected_at=now,
            )
        ],
    )
    return ingest_scan(db_session, server, payload)


def test_list_findings_no_filters_returns_all(db_session):
    server = _server(db_session)
    _seed_scan_with_findings(
        db_session,
        server,
        [
            _finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL),
            _finding("SSH-001", GuardianCategory.SSH, Severity.HIGH),
        ],
    )

    results = list_findings(db_session)
    assert len(results) == 2


def test_list_findings_filter_by_server(db_session):
    server1 = _server(db_session, "web01")
    server2 = _server(db_session, "web02")
    _seed_scan_with_findings(
        db_session, server1, [_finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL)]
    )
    _seed_scan_with_findings(
        db_session, server2, [_finding("SSH-001", GuardianCategory.SSH, Severity.HIGH)]
    )

    results = list_findings(db_session, server_id=server1.id)
    assert len(results) == 1
    assert results[0].check_id == "PERM-001"


def test_list_findings_filter_by_severity(db_session):
    server = _server(db_session)
    _seed_scan_with_findings(
        db_session,
        server,
        [
            _finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL),
            _finding("SSH-001", GuardianCategory.SSH, Severity.LOW),
        ],
    )

    results = list_findings(db_session, severity="critical")
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL


def test_list_findings_filter_by_category(db_session):
    server = _server(db_session)
    _seed_scan_with_findings(
        db_session,
        server,
        [
            _finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL),
            _finding("SSH-001", GuardianCategory.SSH, Severity.LOW),
        ],
    )

    results = list_findings(db_session, category="ssh")
    assert len(results) == 1
    assert results[0].module == GuardianCategory.SSH


def test_list_findings_filter_by_status(db_session):
    server = _server(db_session)
    _seed_scan_with_findings(
        db_session, server, [_finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL)]
    )

    open_results = list_findings(db_session, status="open")
    resolved_results = list_findings(db_session, status="resolved")
    assert len(open_results) == 1
    assert len(resolved_results) == 0


def test_list_findings_filter_by_scan_id(db_session):
    server = _server(db_session)
    scan1 = _seed_scan_with_findings(
        db_session, server, [_finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL)]
    )
    _seed_scan_with_findings(
        db_session, server, [_finding("SSH-001", GuardianCategory.SSH, Severity.LOW)]
    )

    results = list_findings(db_session, scan_id=scan1.id)
    assert len(results) == 1
    assert results[0].check_id == "PERM-001"


def test_list_findings_empty_when_no_data(db_session):
    assert list_findings(db_session) == []


def test_explain_finding_found(db_session):
    server = _server(db_session)
    _seed_scan_with_findings(
        db_session, server, [_finding("PERM-001", GuardianCategory.PERMISSION, Severity.CRITICAL)]
    )
    findings = list_findings(db_session)
    detail = explain_finding(db_session, findings[0].id)
    assert detail.check_id == "PERM-001"
    assert detail.why_it_matters == "why it matters"


def test_explain_finding_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        explain_finding(db_session, "nonexistent-id")
