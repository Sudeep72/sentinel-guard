"""Server registration and lookup — the multi-agent fleet backbone.

Every other service that touches a server (scans, findings, scores)
goes through here first to resolve a ``server_id`` into a real,
existing ``Server`` row, so "unknown server" is handled in exactly one
place.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard_contracts import ServerInfo, ServerRegistration, ServerStatus
from sqlalchemy.orm import Session

from app.auth.security import generate_api_key, hash_api_key
from app.core.exceptions import NotFoundError
from app.models.server import Server


def _to_server_info(server: Server) -> ServerInfo:
    return ServerInfo(
        id=server.id,
        hostname=server.hostname,
        ip_address=server.ip_address,
        distro=server.distro,  # type: ignore[arg-type]  # stored as validated enum value string
        distro_version=server.distro_version,
        agent_version=server.agent_version,
        status=server.status,  # type: ignore[arg-type]
        last_seen_at=server.last_seen_at,
        created_at=server.created_at,
    )


def register_server(db: Session, registration: ServerRegistration) -> tuple[ServerInfo, str]:
    """Register an agent, or re-register (upsert) if its hostname already exists.

    Idempotent by hostname: registering the same hostname twice does
    NOT create a second server row. Instead, the existing server's
    metadata (distro, distro_version, agent_version, ip_address) is
    refreshed and a brand new API key is issued, invalidating the old
    one. This matches how re-enrolling an agent works in most fleet
    management tools (Wazuh, Osquery Fleet, Datadog) — re-registering
    means "this is still the same machine, give it a fresh credential,"
    not "create another record for it."

    Before this upsert behavior existed, registering the same host
    multiple times (e.g. re-running a setup script, or losing the
    issued API key and registering again to get a new one) silently
    created multiple Server rows for one physical machine, fragmenting
    its scan history and score across several server_ids in the fleet
    view. ``hostname`` also has a unique DB constraint (see the
    accompanying migration) as defense in depth against races.

    Returns:
        A tuple of ``(ServerInfo, plaintext_api_key)``. The plaintext
        key is returned exactly once — only its SHA-256 hash is
        persisted — so the caller (the REST endpoint) must hand it back
        to the agent in this same response.
    """
    existing = db.query(Server).filter(Server.hostname == registration.hostname).one_or_none()
    plaintext_key = generate_api_key()

    if existing is not None:
        existing.ip_address = registration.ip_address
        existing.distro = registration.distro.value
        existing.distro_version = registration.distro_version
        existing.agent_version = registration.agent_version
        existing.api_key_hash = hash_api_key(plaintext_key)
        existing.status = ServerStatus.ONLINE.value
        existing.last_seen_at = datetime.now(UTC)
        db.commit()
        db.refresh(existing)
        return _to_server_info(existing), plaintext_key

    server = Server(
        hostname=registration.hostname,
        ip_address=registration.ip_address,
        distro=registration.distro.value,
        distro_version=registration.distro_version,
        agent_version=registration.agent_version,
        api_key_hash=hash_api_key(plaintext_key),
        status=ServerStatus.ONLINE.value,
        last_seen_at=datetime.now(UTC),
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return _to_server_info(server), plaintext_key


def list_servers(db: Session) -> list[ServerInfo]:
    """Return every registered server (the whole fleet)."""
    servers = db.query(Server).order_by(Server.hostname).all()
    return [_to_server_info(s) for s in servers]


def get_server(db: Session, server_id: str) -> ServerInfo:
    """Fetch a single server by id.

    Raises:
        NotFoundError: If no server with this id is registered.
    """
    server = db.get(Server, server_id)
    if server is None:
        raise NotFoundError(f"No server registered with id {server_id!r}")
    return _to_server_info(server)


def get_server_orm_or_none(db: Session, server_id: str) -> Server | None:
    """Fetch the raw ORM Server row (internal use by other services)."""
    return db.get(Server, server_id)


def touch_last_seen(db: Session, server: Server) -> None:
    """Mark a server online and update its last-seen timestamp.

    Called whenever an authenticated agent request comes in (currently:
    scan submission) — this is what lets ``status`` reflect real fleet
    connectivity rather than only updating at registration time.
    """
    server.last_seen_at = datetime.now(UTC)
    server.status = ServerStatus.ONLINE.value
    db.add(server)
    db.commit()
