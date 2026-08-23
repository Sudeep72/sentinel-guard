"""Security score lookup.

Reads whatever the Scoring Engine (``scoring_service.compute_security_score``,
Phase 18) has written to ``security_scores`` / ``category_scores``.
This is the READ half of scoring; ``scoring_service`` is the WRITE half
— both REST and MCP call this same function, so a human checking the
dashboard and an AI asking "what's my score" always see identical
numbers.

Scoring happens automatically at scan-ingest time (see
``scan_service.ingest_scan``), so in normal operation a score already
exists here immediately after a scan completes. The "not yet computed"
path below is retained defensively (e.g. if score computation
previously failed) rather than assumed unreachable.
"""

from __future__ import annotations

from sentinelguard_contracts import CategoryScore, GuardianCategory, SecurityScore
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.score import CategoryScoreRecord, SecurityScoreRecord
from app.schemas.scores import SecurityScoreResponse
from app.services.scan_service import get_latest_scan
from app.services.server_service import get_server_orm_or_none

_NOT_YET_COMPUTED_MESSAGE = (
    "No security score has been computed for this scan yet. Scoring runs "
    "automatically at scan-ingest time, so this typically means scoring "
    "failed for this specific scan — check the dashboard logs."
)


def get_security_score(
    db: Session, server_id: str, scan_id: str | None = None
) -> SecurityScoreResponse:
    """Get the security score for a server's scan.

    Args:
        server_id: Which server.
        scan_id: Specific scan, or the server's latest scan if omitted.

    Raises:
        NotFoundError: If the server doesn't exist, or no scan_id was
            given and the server has no scans yet.
    """
    server = get_server_orm_or_none(db, server_id)
    if server is None:
        raise NotFoundError(f"No server registered with id {server_id!r}")

    if scan_id is None:
        latest = get_latest_scan(db, server_id)
        if latest is None:
            raise NotFoundError(f"Server {server_id!r} has no scans yet")
        scan_id = latest.id

    score_row = (
        db.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan_id).one_or_none()
    )
    if score_row is None:
        return SecurityScoreResponse(available=False, message=_NOT_YET_COMPUTED_MESSAGE)

    category_rows = (
        db.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan_id).all()
    )
    category_scores = [
        CategoryScore(
            category=GuardianCategory(row.category),
            score=row.score,
            weight=row.weight_used,
        )
        for row in category_rows
    ]

    score = SecurityScore(
        scan_id=scan_id,
        overall_score=score_row.overall_score,
        category_scores=category_scores,
        computed_at=score_row.computed_at,
    )
    return SecurityScoreResponse(
        available=True,
        score=score,
        total_checks=score_row.total_checks,
        passed_checks=score_row.passed_checks,
        failed_checks=score_row.failed_checks,
        baseline_version=score_row.baseline_version,
    )
