from datetime import UTC

import pytest
from sentinelguard_contracts import Distro, ServerRegistration

from app.core.exceptions import NotFoundError
from app.modules.ownership.analyzer import OwnershipAnalyzer
from app.modules.permission.analyzer import PermissionAnalyzer
from app.modules.registry import clear_registry, register_analyzer
from app.modules.ssh.analyzer import SSHAnalyzer
from app.services.baseline_service import compare_to_baseline
from app.services.server_service import register_server


def _server(db_session, hostname="web01", distro=Distro.UBUNTU):
    registration = ServerRegistration(
        hostname=hostname, distro=distro, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return info


@pytest.fixture(autouse=True)
def _register():
    clear_registry()
    register_analyzer(PermissionAnalyzer())
    register_analyzer(OwnershipAnalyzer())
    register_analyzer(SSHAnalyzer())
    yield
    clear_registry()


def test_compare_to_baseline_server_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        compare_to_baseline(db_session, server_id="nonexistent-id")


def test_compare_to_baseline_no_scans_returns_not_available(db_session):
    server = _server(db_session)
    response = compare_to_baseline(db_session, server_id=server.id)
    assert response.available is False
    assert "No scans" in response.message


def _ingest_empty_scan(db_session, server):
    from datetime import datetime, timedelta

    from sentinelguard_contracts import ScanPayload, ScanStatus

    from app.services.scan_service import ingest_scan

    now = datetime.now(UTC)
    return ingest_scan(
        db_session,
        server,
        ScanPayload(
            server_id=server.id,
            hostname=server.hostname,
            distro=Distro.UBUNTU,
            distro_version="24.04",
            agent_version="0.1.0",
            started_at=now - timedelta(seconds=5),
            completed_at=now,
            status=ScanStatus.COMPLETED,
            guardian_results=[],
        ),
    )


def test_compare_to_baseline_returns_real_comparisons(db_session):
    from app.services.server_service import get_server_orm_or_none

    server_info = _server(db_session, distro=Distro.UBUNTU)
    server = get_server_orm_or_none(db_session, server_info.id)
    _ingest_empty_scan(db_session, server)

    response = compare_to_baseline(db_session, server_id=server.id)
    assert response.available is True
    assert len(response.comparisons) > 0


def test_compare_to_baseline_filter_by_category(db_session):
    from app.services.server_service import get_server_orm_or_none

    server_info = _server(db_session, distro=Distro.UBUNTU)
    server = get_server_orm_or_none(db_session, server_info.id)
    _ingest_empty_scan(db_session, server)

    resp = compare_to_baseline(db_session, server_id=server.id, category="ssh")
    assert resp.available is True
    assert all(c.category == "ssh" for c in resp.comparisons)


def test_compare_to_baseline_unknown_category_not_available(db_session):
    from app.services.server_service import get_server_orm_or_none

    server_info = _server(db_session, distro=Distro.UBUNTU)
    server = get_server_orm_or_none(db_session, server_info.id)
    _ingest_empty_scan(db_session, server)

    response = compare_to_baseline(db_session, server_id=server.id, category="nonexistent")
    assert response.available is False
