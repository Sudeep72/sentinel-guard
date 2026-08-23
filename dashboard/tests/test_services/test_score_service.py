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
from app.services.scan_service import ingest_scan
from app.services.score_service import get_security_score
from app.services.server_service import get_server_orm_or_none, register_server


def _server(db_session, hostname="web01"):
    registration = ServerRegistration(
        hostname=hostname, distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _scan(db_session, server, guardian_results=None):
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
        guardian_results=guardian_results or [],
    )
    return ingest_scan(db_session, server, payload)


def _finding(check_id, module, severity) -> Finding:
    return Finding(
        check_id=check_id,
        module=module,
        title=f"Finding {check_id}",
        severity=severity,
        description="d",
        why_it_matters="w",
        attack_scenario="s",
        recommendation="r",
    )


def test_get_security_score_server_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        get_security_score(db_session, server_id="nonexistent-id")


def test_get_security_score_no_scans_raises(db_session):
    server = _server(db_session)
    with pytest.raises(NotFoundError):
        get_security_score(db_session, server_id=server.id)


def test_get_security_score_available_immediately_after_scan(db_session):
    """Scoring is now automatic — a score exists right after ingest_scan()."""
    server = _server(db_session)
    _scan(db_session, server)

    response = get_security_score(db_session, server_id=server.id)

    assert response.available is True
    assert response.score is not None
    assert response.score.overall_score == 100.0  # no findings = perfect score
    assert len(response.score.category_scores) == 9  # all nine Guardian categories


def test_get_security_score_reflects_findings_severity(db_session):
    server = _server(db_session)
    now = datetime.now(UTC)
    guardian_results = [
        GuardianResult(
            module=GuardianCategory.SSH,
            status=GuardianRunStatus.OK,
            findings=[_finding("SSH-001", GuardianCategory.SSH, Severity.CRITICAL)],
            collected_at=now,
        )
    ]
    scan = _scan(db_session, server, guardian_results)

    response = get_security_score(db_session, server_id=server.id, scan_id=scan.id)

    assert response.available is True
    ssh_score = next(
        c for c in response.score.category_scores if c.category == GuardianCategory.SSH
    )
    assert ssh_score.score == 75.0  # 100 - 25 (critical penalty)


def test_get_security_score_includes_pass_fail_and_baseline_version(db_session):
    server = _server(db_session)
    scan = _scan(db_session, server)

    response = get_security_score(db_session, server_id=server.id, scan_id=scan.id)

    assert response.total_checks is not None
    assert response.passed_checks is not None
    assert response.failed_checks is not None
    assert response.baseline_version == "1.0.0"


def test_get_security_score_uses_specific_scan_id(db_session):
    server = _server(db_session)
    scan1 = _scan(db_session, server)
    now = datetime.now(UTC)
    scan2 = _scan(
        db_session,
        server,
        [
            GuardianResult(
                module=GuardianCategory.SSH,
                status=GuardianRunStatus.OK,
                findings=[_finding("SSH-001", GuardianCategory.SSH, Severity.HIGH)],
                collected_at=now,
            )
        ],
    )

    response_scan1 = get_security_score(db_session, server_id=server.id, scan_id=scan1.id)
    response_scan2 = get_security_score(db_session, server_id=server.id, scan_id=scan2.id)

    assert response_scan1.score.overall_score == 100.0
    assert response_scan2.score.overall_score < 100.0


def test_recompute_is_idempotent_not_duplicated(db_session):
    """Calling ingest_scan (which triggers scoring) doesn't fail on recompute."""
    from app.services.scoring_service import compute_security_score

    server = _server(db_session)
    scan = _scan(db_session, server)

    # Manually recompute again for the same scan — must not raise a
    # UNIQUE constraint error, and must not create duplicate rows.
    compute_security_score(db_session, server, scan)
    compute_security_score(db_session, server, scan)

    from app.models.score import CategoryScoreRecord, SecurityScoreRecord

    score_rows = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).all()
    )
    category_rows = (
        db_session.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).all()
    )
    assert len(score_rows) == 1
    assert len(category_rows) == 9
