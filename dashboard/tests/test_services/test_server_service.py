import pytest
from sentinelguard_contracts import Distro, ServerRegistration, ServerStatus

from app.core.exceptions import NotFoundError
from app.services.server_service import (
    get_server,
    get_server_orm_or_none,
    list_servers,
    register_server,
    touch_last_seen,
)


def _registration(hostname="web01") -> ServerRegistration:
    return ServerRegistration(
        hostname=hostname,
        ip_address="10.0.0.5",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
    )


def test_register_server_returns_info_and_plaintext_key(db_session):
    server_info, api_key = register_server(db_session, _registration())

    assert server_info.hostname == "web01"
    assert server_info.distro == Distro.UBUNTU
    assert server_info.status == ServerStatus.ONLINE
    assert isinstance(api_key, str)
    assert len(api_key) > 32


def test_register_server_persists_hashed_not_plaintext_key(db_session):
    server_info, api_key = register_server(db_session, _registration())

    server = get_server_orm_or_none(db_session, server_info.id)
    assert server is not None
    assert server.api_key_hash != api_key


def test_register_two_servers_get_different_ids_and_keys(db_session):
    info1, key1 = register_server(db_session, _registration("web01"))
    info2, key2 = register_server(db_session, _registration("web02"))

    assert info1.id != info2.id
    assert key1 != key2


def test_list_servers_returns_all_registered(db_session):
    register_server(db_session, _registration("web01"))
    register_server(db_session, _registration("api01"))

    servers = list_servers(db_session)
    hostnames = {s.hostname for s in servers}
    assert hostnames == {"web01", "api01"}


def test_list_servers_empty_fleet(db_session):
    assert list_servers(db_session) == []


def test_get_server_found(db_session):
    info, _ = register_server(db_session, _registration())
    fetched = get_server(db_session, info.id)
    assert fetched.id == info.id
    assert fetched.hostname == "web01"


def test_get_server_not_found_raises(db_session):
    with pytest.raises(NotFoundError):
        get_server(db_session, "nonexistent-id")


def test_get_server_orm_or_none_returns_none_for_missing(db_session):
    assert get_server_orm_or_none(db_session, "nonexistent-id") is None


def test_touch_last_seen_updates_status_and_timestamp(db_session):
    info, _ = register_server(db_session, _registration())
    server = get_server_orm_or_none(db_session, info.id)
    original_last_seen = server.last_seen_at

    server.status = "offline"
    db_session.commit()

    touch_last_seen(db_session, server)

    refreshed = get_server_orm_or_none(db_session, info.id)
    assert refreshed.status == "online"
    assert refreshed.last_seen_at >= original_last_seen


# ── Re-registration is an idempotent upsert, not a duplicate (bug fix) ──────


def test_reregistering_same_hostname_does_not_create_duplicate(db_session):
    info1, _ = register_server(db_session, _registration("web01"))
    info2, _ = register_server(db_session, _registration("web01"))

    assert info1.id == info2.id
    servers = list_servers(db_session)
    assert sum(1 for s in servers if s.hostname == "web01") == 1


def test_reregistering_same_hostname_rotates_api_key(db_session):
    _, key1 = register_server(db_session, _registration("web01"))
    _, key2 = register_server(db_session, _registration("web01"))

    assert key1 != key2


def test_reregistering_same_hostname_old_key_stops_working(db_session):
    from app.auth.security import hash_api_key

    _, old_key = register_server(db_session, _registration("web01"))
    info, new_key = register_server(db_session, _registration("web01"))

    server = get_server_orm_or_none(db_session, info.id)
    assert server.api_key_hash == hash_api_key(new_key)
    assert server.api_key_hash != hash_api_key(old_key)


def test_reregistering_same_hostname_updates_metadata(db_session):
    register_server(db_session, _registration("web01"))

    updated = ServerRegistration(
        hostname="web01",
        ip_address="10.0.0.99",
        distro=Distro.DEBIAN,
        distro_version="12",
        agent_version="2.0.0",
    )
    info2, _ = register_server(db_session, updated)

    assert info2.distro == Distro.DEBIAN
    assert info2.distro_version == "12"
    assert info2.agent_version == "2.0.0"
    assert info2.ip_address == "10.0.0.99"


def test_reregistering_preserves_scan_history(db_session):
    from datetime import UTC, datetime, timedelta

    from sentinelguard_contracts import ScanPayload, ScanStatus

    from app.services.scan_service import ingest_scan
    from app.services.server_service import get_server_orm_or_none as get_orm

    info1, _ = register_server(db_session, _registration("web01"))
    server = get_orm(db_session, info1.id)
    now = datetime.now(UTC)
    ingest_scan(
        db_session,
        server,
        ScanPayload(
            server_id=server.id,
            hostname="web01",
            distro=Distro.UBUNTU,
            distro_version="24.04",
            agent_version="0.1.0",
            started_at=now - timedelta(seconds=5),
            completed_at=now,
            status=ScanStatus.COMPLETED,
            guardian_results=[],
        ),
    )

    # Re-register the same hostname (e.g. lost API key, re-ran setup)
    info2, _ = register_server(db_session, _registration("web01"))

    from app.services.scan_service import list_scans_for_server

    assert info2.id == info1.id
    assert len(list_scans_for_server(db_session, info2.id)) == 1


def test_different_hostnames_still_get_separate_rows(db_session):
    info1, _ = register_server(db_session, _registration("web01"))
    info2, _ = register_server(db_session, _registration("web02"))

    assert info1.id != info2.id
    assert len(list_servers(db_session)) == 2
