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
from app.services.scan_service import (
    get_latest_scan,
    get_scan,
    ingest_scan,
    list_scans_for_server,
)
from app.services.server_service import get_server_orm_or_none, register_server


def _server(db_session, hostname="web01"):
    registration = ServerRegistration(
        hostname=hostname, distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _finding(check_id="PERM-001") -> Finding:
    return Finding(
        check_id=check_id,
        module=GuardianCategory.PERMISSION,
        title="/etc/shadow is world-readable",
        severity=Severity.CRITICAL,
        description="/etc/shadow has mode 644.",
        why_it_matters="Password hashes become readable.",
        attack_scenario="Offline cracking becomes possible.",
        recommendation="chmod 600 /etc/shadow",
        current_value="644",
        expected_value="600",
    )


def _payload(server_id=None, status=ScanStatus.COMPLETED, findings=None) -> ScanPayload:
    now = datetime.now(UTC)
    guardian_results = []
    if findings is not None:
        guardian_results.append(
            GuardianResult(
                module=GuardianCategory.PERMISSION,
                status=GuardianRunStatus.OK,
                findings=findings,
                collected_at=now,
            )
        )
    return ScanPayload(
        server_id=server_id,
        hostname="web01",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=now - timedelta(seconds=5),
        completed_at=now,
        status=status,
        guardian_results=guardian_results,
    )


def test_ingest_scan_persists_scan_and_findings(db_session):
    server = _server(db_session)
    payload = _payload(findings=[_finding()])

    scan = ingest_scan(db_session, server, payload)

    assert scan.server_id == server.id
    assert scan.status == "completed"

    scans = list_scans_for_server(db_session, server.id)
    assert len(scans) == 1
    assert scans[0].id == scan.id


def test_ingest_scan_attributes_to_authenticated_server_not_payload_claim(db_session):
    server = _server(db_session, "web01")
    other_server = _server(db_session, "web02")

    # payload claims a different server_id than the authenticated one
    payload = _payload(server_id=other_server.id)
    scan = ingest_scan(db_session, server, payload)

    assert scan.server_id == server.id
    assert scan.server_id != other_server.id


def test_ingest_scan_creates_findings_with_correct_fields(db_session):
    server = _server(db_session)
    payload = _payload(findings=[_finding()])

    scan = ingest_scan(db_session, server, payload)

    from app.models.finding import Finding as FindingModel

    rows = db_session.query(FindingModel).filter(FindingModel.scan_id == scan.id).all()
    assert len(rows) == 1
    assert rows[0].check_id == "PERM-001"
    assert rows[0].severity == "critical"
    assert rows[0].status == "open"
    assert rows[0].server_id == server.id


def test_ingest_scan_updates_server_last_seen_and_status(db_session):
    server = _server(db_session)
    server.status = "offline"
    db_session.commit()

    payload = _payload()
    ingest_scan(db_session, server, payload)

    refreshed = get_server_orm_or_none(db_session, server.id)
    assert refreshed.status == "online"
    assert refreshed.last_seen_at is not None


def test_ingest_scan_with_no_findings(db_session):
    server = _server(db_session)
    payload = _payload()
    scan = ingest_scan(db_session, server, payload)
    assert scan is not None


def test_get_scan_found(db_session):
    server = _server(db_session)
    scan = ingest_scan(db_session, server, _payload())
    fetched = get_scan(db_session, scan.id)
    assert fetched.id == scan.id


def test_get_scan_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        get_scan(db_session, "nonexistent-id")


def test_get_latest_scan_returns_none_when_no_scans(db_session):
    server = _server(db_session)
    assert get_latest_scan(db_session, server.id) is None


def test_get_latest_scan_returns_most_recent(db_session):
    server = _server(db_session)
    ingest_scan(db_session, server, _payload())
    import time

    time.sleep(0.01)
    second = ingest_scan(db_session, server, _payload())

    latest = get_latest_scan(db_session, server.id)
    assert latest.id == second.id


def test_list_scans_for_server_ordered_most_recent_first(db_session):
    server = _server(db_session)
    first = ingest_scan(db_session, server, _payload())
    import time

    time.sleep(0.01)
    second = ingest_scan(db_session, server, _payload())

    scans = list_scans_for_server(db_session, server.id)
    assert [s.id for s in scans] == [second.id, first.id]
