"""Scan ingestion — turns an agent's ScanPayload into persisted Scan and
Finding rows, triggers automatic scoring, and provides lookup for
"latest scan" queries used by baseline comparison and reports.
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import FindingStatus, ScanPayload
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.finding import Finding as FindingModel
from app.models.scan import Scan
from app.models.server import Server
from app.services.server_service import touch_last_seen

logger = logging.getLogger(__name__)


def ingest_scan(db: Session, server: Server, payload: ScanPayload) -> Scan:
    """Persist a scan and its findings, mark the server online, and
    automatically compute its security score.

    Args:
        db: Active database session.
        server: The authenticated agent's Server row (from
            ``get_current_server``) — the scan is always attributed to
            whichever server the API key belongs to, never to whatever
            ``payload.server_id`` claims, to prevent one agent from
            submitting scans on another server's behalf.
        payload: The validated ScanPayload from the agent.
    """
    scan = Scan(
        server_id=server.id,
        started_at=payload.started_at,
        completed_at=payload.completed_at,
        status=payload.status.value,
        agent_version=payload.agent_version,
    )
    db.add(scan)
    db.flush()  # assign scan.id before creating findings that reference it

    for guardian_result in payload.guardian_results:
        for finding in guardian_result.findings:
            db.add(
                FindingModel(
                    scan_id=scan.id,
                    server_id=server.id,
                    module=finding.module.value,
                    check_id=finding.check_id,
                    title=finding.title,
                    severity=finding.severity.value,
                    description=finding.description,
                    why_it_matters=finding.why_it_matters,
                    attack_scenario=finding.attack_scenario,
                    recommendation=finding.recommendation,
                    current_value=finding.current_value,
                    expected_value=finding.expected_value,
                    status=FindingStatus.OPEN.value,
                )
            )

    # Keep the server's recorded distro/agent_version fresh in case of
    # OS upgrades or agent version bumps between scans.
    server.distro = payload.distro.value
    server.distro_version = payload.distro_version
    server.agent_version = payload.agent_version

    db.commit()
    db.refresh(scan)
    touch_last_seen(db, server)

    _compute_score_defensively(db, server, scan)

    return scan


def _compute_score_defensively(db: Session, server: Server, scan: Scan) -> None:
    """Compute the scan's security score, logging (not raising) on failure.

    Scoring is a derived, best-effort feature layered on top of a scan
    that has already been successfully persisted — a scoring bug should
    never cause scan ingestion itself to fail and return an error to the
    agent. Scores can always be recomputed later once the underlying
    issue is fixed (compute_security_score is idempotent).
    """
    try:
        from app.services.scoring_service import compute_security_score

        compute_security_score(db, server, scan)
    except Exception:  # noqa: BLE001 - defensive boundary, see docstring
        logger.exception("Failed to compute security score for scan %s", scan.id)


def get_scan(db: Session, scan_id: str) -> Scan:
    """Fetch a scan by id.

    Raises:
        NotFoundError: If no scan with this id exists.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"No scan found with id {scan_id!r}")
    return scan


def get_latest_scan(db: Session, server_id: str) -> Scan | None:
    """Return the most recently completed scan for a server, or None."""
    return (
        db.query(Scan)
        .filter(Scan.server_id == server_id)
        .order_by(Scan.completed_at.desc())
        .first()
    )


def list_scans_for_server(db: Session, server_id: str) -> list[Scan]:
    """Return every scan for a server, most recent first."""
    return (
        db.query(Scan).filter(Scan.server_id == server_id).order_by(Scan.completed_at.desc()).all()
    )
