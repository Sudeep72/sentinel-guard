"""Tests for scoring_service (Phase 18)."""

from __future__ import annotations

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

from app.models.score import CategoryScoreRecord, SecurityScoreRecord
from app.services.scan_service import ingest_scan
from app.services.scoring_service import (
    CATEGORY_WEIGHTS,
    SEVERITY_WEIGHTS,
    compute_security_score,
)
from app.services.server_service import get_server_orm_or_none, register_server


def _server(db_session, hostname="web01", distro=Distro.UBUNTU):
    registration = ServerRegistration(
        hostname=hostname, distro=distro, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _finding(check_id: str, module: GuardianCategory, severity: Severity) -> Finding:
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


def _scan_with_findings(db_session, server, findings_by_category: dict):
    now = datetime.now(UTC)
    guardian_results = [
        GuardianResult(
            module=category,
            status=GuardianRunStatus.OK,
            findings=findings,
            collected_at=now,
        )
        for category, findings in findings_by_category.items()
    ]
    payload = ScanPayload(
        server_id=server.id,
        hostname=server.hostname,
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=now - timedelta(seconds=5),
        completed_at=now,
        status=ScanStatus.COMPLETED,
        guardian_results=guardian_results,
    )
    return ingest_scan(db_session, server, payload)


# ── Weight table invariants ──────────────────────────────────────────────────


def test_category_weights_sum_to_one():
    assert abs(sum(CATEGORY_WEIGHTS.values()) - 1.0) < 1e-9


def test_category_weights_cover_all_nine_categories():
    assert set(CATEGORY_WEIGHTS.keys()) == set(GuardianCategory)


def test_severity_weights_cover_all_severities():
    assert set(SEVERITY_WEIGHTS.keys()) == set(Severity)


def test_severity_weights_monotonically_decrease():
    assert (
        SEVERITY_WEIGHTS[Severity.CRITICAL]
        > SEVERITY_WEIGHTS[Severity.HIGH]
        > SEVERITY_WEIGHTS[Severity.MEDIUM]
        > SEVERITY_WEIGHTS[Severity.LOW]
        > SEVERITY_WEIGHTS[Severity.INFO]
    )


def test_invalid_weight_table_raises_at_import_time():
    """The module-level _validate_weights() guard would reject a bad table."""
    import app.services.scoring_service as scoring_module
    from app.services.scoring_service import _validate_weights

    original = dict(scoring_module.CATEGORY_WEIGHTS)
    try:
        scoring_module.CATEGORY_WEIGHTS[GuardianCategory.SSH] = 0.99
        with pytest.raises(ValueError, match="must sum to 1.0"):
            _validate_weights()
    finally:
        scoring_module.CATEGORY_WEIGHTS.clear()
        scoring_module.CATEGORY_WEIGHTS.update(original)


# ── compute_security_score: no findings ─────────────────────────────────────


def test_no_findings_gives_perfect_score(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    score = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    assert score.overall_score == 100.0
    assert score.total_checks >= 0
    assert score.passed_checks == score.total_checks
    assert score.failed_checks == 0


def test_no_findings_all_nine_categories_scored_100(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    rows = (
        db_session.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).all()
    )
    assert len(rows) == 9
    for row in rows:
        assert row.score == 100.0


# ── Severity penalty math ────────────────────────────────────────────────────


def test_single_critical_finding_penalty(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(
        db_session,
        server,
        {GuardianCategory.SSH: [_finding("SSH-001", GuardianCategory.SSH, Severity.CRITICAL)]},
    )

    ssh_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "ssh")
        .one()
    )
    assert ssh_row.score == 75.0  # 100 - 25


def test_multiple_findings_penalty_stacks(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(
        db_session,
        server,
        {
            GuardianCategory.SSH: [
                _finding("SSH-001", GuardianCategory.SSH, Severity.CRITICAL),
                _finding("SSH-002", GuardianCategory.SSH, Severity.HIGH),
            ]
        },
    )

    ssh_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "ssh")
        .one()
    )
    assert ssh_row.score == 60.0  # 100 - 25 - 15


def test_score_floors_at_zero_not_negative(db_session):
    server = _server(db_session)
    # 5 criticals = 125 penalty, way over 100
    findings = [_finding(f"SSH-{i:03d}", GuardianCategory.SSH, Severity.CRITICAL) for i in range(5)]
    scan = _scan_with_findings(db_session, server, {GuardianCategory.SSH: findings})

    ssh_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "ssh")
        .one()
    )
    assert ssh_row.score == 0.0  # floored, not -25


def test_info_severity_has_zero_penalty(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(
        db_session,
        server,
        {GuardianCategory.SSH: [_finding("SSH-001", GuardianCategory.SSH, Severity.INFO)]},
    )

    ssh_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "ssh")
        .one()
    )
    assert ssh_row.score == 100.0


# ── Overall score = weighted average ─────────────────────────────────────────


def test_overall_score_matches_weighted_formula(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(
        db_session,
        server,
        {GuardianCategory.SSH: [_finding("SSH-001", GuardianCategory.SSH, Severity.CRITICAL)]},
    )

    overall = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    # SSH scores 75, all other 8 categories score 100.
    # overall = 75*0.20 + 100*(0.80) = 15 + 80 = 95
    expected = 75.0 * CATEGORY_WEIGHTS[GuardianCategory.SSH] + 100.0 * (
        1 - CATEGORY_WEIGHTS[GuardianCategory.SSH]
    )
    assert abs(overall.overall_score - expected) < 0.01


def test_category_score_isolation_findings_dont_leak_across_categories(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(
        db_session,
        server,
        {
            GuardianCategory.DOCKER: [
                _finding("DOCKER-006", GuardianCategory.DOCKER, Severity.CRITICAL)
            ]
        },
    )

    ssh_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "ssh")
        .one()
    )
    docker_row = (
        db_session.query(CategoryScoreRecord)
        .filter(CategoryScoreRecord.scan_id == scan.id, CategoryScoreRecord.category == "docker")
        .one()
    )
    assert ssh_row.score == 100.0  # unaffected by docker finding
    assert docker_row.score == 75.0


# ── Idempotent recompute ─────────────────────────────────────────────────────


def test_recompute_replaces_not_duplicates(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})  # scored once automatically by ingest_scan

    compute_security_score(db_session, server, scan)  # recompute manually

    score_rows = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).all()
    )
    category_rows = (
        db_session.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).all()
    )
    assert len(score_rows) == 1
    assert len(category_rows) == 9


def test_recompute_after_findings_change_updates_score(db_session):
    """If findings are added after the first automatic score, a manual
    recompute reflects the new state."""
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})
    first_score = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    assert first_score.overall_score == 100.0

    # Manually add a finding to simulate a later-discovered issue, then recompute.
    from sentinelguard_contracts import FindingStatus

    from app.models.finding import Finding as FindingModel

    db_session.add(
        FindingModel(
            scan_id=scan.id,
            server_id=server.id,
            module="ssh",
            check_id="SSH-001",
            title="test",
            severity="critical",
            description="d",
            why_it_matters="w",
            attack_scenario="s",
            recommendation="r",
            status=FindingStatus.OPEN.value,
        )
    )
    db_session.commit()

    compute_security_score(db_session, server, scan)

    updated_score = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    assert updated_score.overall_score < 100.0


# ── baseline_version tracking ─────────────────────────────────────────────────


def test_baseline_version_recorded_on_score(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    score = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    assert score.baseline_version == "1.0.0"


# ── Pass/fail counts derived from baseline comparison ────────────────────────


def test_pass_fail_counts_are_nonnegative_and_consistent(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    score = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )
    assert score.total_checks == score.passed_checks + score.failed_checks
    assert score.passed_checks >= 0
    assert score.failed_checks >= 0


def test_category_pass_fail_sums_to_security_score_total(db_session):
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    category_rows = (
        db_session.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).all()
    )
    security_row = (
        db_session.query(SecurityScoreRecord).filter(SecurityScoreRecord.scan_id == scan.id).one()
    )

    assert sum(r.passed_checks for r in category_rows) == security_row.passed_checks
    assert sum(r.failed_checks for r in category_rows) == security_row.failed_checks


# ── No Guardian-specific scoring logic (generic iteration) ───────────────────


def test_every_category_gets_a_score_row_generically(db_session):
    """Every GuardianCategory produces a CategoryScoreRecord via the same
    generic loop — no special-casing per Guardian."""
    server = _server(db_session)
    scan = _scan_with_findings(db_session, server, {})

    rows = (
        db_session.query(CategoryScoreRecord).filter(CategoryScoreRecord.scan_id == scan.id).all()
    )
    scored_categories = {row.category for row in rows}
    expected_categories = {c.value for c in GuardianCategory}
    assert scored_categories == expected_categories
