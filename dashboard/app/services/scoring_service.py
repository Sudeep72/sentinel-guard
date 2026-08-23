"""Scoring Engine (Phase 18).

Computes and persists the security score for a scan. This is the
single source of truth both the REST ``/servers/{id}/score`` endpoint
and the MCP ``get_security_score`` tool read from (via
``score_service.get_security_score``) — this module only *writes*
scores; reading them is ``score_service``'s job.

**No Guardian-specific scoring code exists.** The engine iterates the
generic ``GuardianCategory`` enum and two fixed lookup tables
(``SEVERITY_WEIGHTS``, ``CATEGORY_WEIGHTS``) — adding a tenth Guardian
in a future version means adding one entry to ``CATEGORY_WEIGHTS`` (and
rebalancing the other nine so they still sum to 1.0), not writing new
scoring logic.

Algorithm (see ARCHITECTURE.md section 7 for the original design):

1. For each category, sum the severity penalty of every open finding:
   critical=25, high=15, medium=7, low=3, info=0.
2. ``category_score = max(0, 100 - total_penalty)``.
3. ``overall_score = sum(category_score * category_weight)`` — since
   the nine category weights sum to exactly 1.0, this is already a
   weighted average with no further division needed.
4. Pass/fail counts come from the Baseline Engine's per-category
   ``compare()`` output (``BaselineComparisonItem.matches_baseline``),
   not from findings directly — this reuses Phase 17's comparison
   logic rather than duplicating "what counts as a check" bookkeeping.
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import GuardianCategory, Severity
from sqlalchemy.orm import Session

from app.models.finding import Finding as FindingModel
from app.models.scan import Scan
from app.models.score import CategoryScoreRecord, SecurityScoreRecord
from app.models.server import Server
from app.modules.baseline_loader import get_baseline_version
from app.modules.registry import get_analyzer
from app.schemas.findings import FindingRecord

logger = logging.getLogger(__name__)

# Severity -> point penalty deducted per open finding.
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

# Category -> weight in the overall score. Must sum to 1.0.
CATEGORY_WEIGHTS: dict[GuardianCategory, float] = {
    GuardianCategory.SSH: 0.20,
    GuardianCategory.SUDO: 0.15,
    GuardianCategory.PERMISSION: 0.15,
    GuardianCategory.SECRET: 0.15,
    GuardianCategory.FIREWALL: 0.15,
    GuardianCategory.DOCKER: 0.10,
    GuardianCategory.KERNEL: 0.05,
    GuardianCategory.CRON: 0.03,
    GuardianCategory.OWNERSHIP: 0.02,
}

_WEIGHT_SUM_TOLERANCE = 1e-6


def _validate_weights() -> None:
    total = sum(CATEGORY_WEIGHTS.values())
    if abs(total - 1.0) > _WEIGHT_SUM_TOLERANCE:
        raise ValueError(f"CATEGORY_WEIGHTS must sum to 1.0, got {total}")


_validate_weights()


def compute_security_score(db: Session, server: Server, scan: Scan) -> SecurityScoreRecord:
    """Compute and persist the security score for one scan.

    Idempotent: re-running for the same scan replaces any existing
    score rows rather than duplicating them, so recomputation (e.g.
    after a scoring formula change) is safe to call repeatedly.

    Args:
        db: Active database session.
        server: The server the scan belongs to (needed for distro-aware
            baseline comparison).
        scan: The scan to score.

    Returns:
        The persisted ``SecurityScoreRecord``.
    """
    findings = _load_findings(db, scan.id)

    category_rows: list[CategoryScoreRecord] = []
    total_checks = 0
    total_passed = 0
    total_failed = 0
    overall_score = 0.0

    for category in GuardianCategory:
        weight = CATEGORY_WEIGHTS[category]
        category_findings = [f for f in findings if f.module == category]

        penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in category_findings)
        category_score = max(0.0, 100.0 - penalty)

        passed, failed = _count_pass_fail(
            category, category_findings, server.distro, server.distro_version
        )

        category_rows.append(
            CategoryScoreRecord(
                scan_id=scan.id,
                category=category.value,
                score=category_score,
                weight_used=weight,
                passed_checks=passed,
                failed_checks=failed,
            )
        )

        overall_score += category_score * weight
        total_checks += passed + failed
        total_passed += passed
        total_failed += failed

    # Idempotent recompute: clear any existing score rows for this scan first.
    db.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).delete()
    db.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).delete()

    for row in category_rows:
        db.add(row)

    security_score = SecurityScoreRecord(
        scan_id=scan.id,
        overall_score=round(overall_score, 2),
        total_checks=total_checks,
        passed_checks=total_passed,
        failed_checks=total_failed,
        baseline_version=get_baseline_version(server.distro),
    )
    db.add(security_score)
    db.commit()
    db.refresh(security_score)

    logger.info(
        "Computed security score for scan %s: overall=%.2f (%d/%d checks passed)",
        scan.id,
        security_score.overall_score,
        total_passed,
        total_checks,
    )
    return security_score


def _load_findings(db: Session, scan_id: str) -> list[FindingRecord]:
    rows = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    return [FindingRecord.model_validate(row) for row in rows]


def _count_pass_fail(
    category: GuardianCategory,
    category_findings: list[FindingRecord],
    distro: str,
    distro_version: str | None,
) -> tuple[int, int]:
    """Derive pass/fail counts from the category's baseline comparison.

    Reuses the Phase 17 analyzer.compare() output rather than
    maintaining a separate "how many checks exist" catalog — each
    BaselineComparisonItem is one check; matches_baseline distinguishes
    pass from fail.
    """
    analyzer = get_analyzer(category)
    if analyzer is None:
        return 0, 0

    comparisons = analyzer.compare(category_findings, distro, distro_version)
    passed = sum(1 for c in comparisons if c.matches_baseline)
    failed = sum(1 for c in comparisons if not c.matches_baseline)
    return passed, failed
