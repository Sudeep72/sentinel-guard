"""Integration tests for the Baseline Engine (Phase 17) and Scoring
Engine (Phase 18) through the full REST + MCP stack."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _reg_body(hostname="srv01"):
    return {
        "hostname": hostname,
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _finding(check_id="SSH-001", module="ssh", severity="critical"):
    return {
        "check_id": check_id,
        "module": module,
        "title": f"Finding {check_id}",
        "severity": severity,
        "description": "d",
        "why_it_matters": "w",
        "attack_scenario": "s",
        "recommendation": "r",
        "current_value": "bad",
        "expected_value": "good",
    }


def _scan_body(server_id, findings=None):
    now = datetime.now(UTC)
    guardian_results = []
    if findings:
        guardian_results.append(
            {
                "module": findings[0]["module"],
                "status": "ok",
                "findings": findings,
                "collected_at": now.isoformat(),
            }
        )
    return {
        "server_id": server_id,
        "hostname": "srv01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "completed_at": now.isoformat(),
        "status": "completed",
        "guardian_results": guardian_results,
    }


# ── REST: score available immediately, reflects findings ────────────────────


def test_score_available_immediately_via_rest(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is True
    assert body["score"]["overall_score"] == 100.0
    assert len(body["score"]["category_scores"]) == 9


def test_score_reflects_real_findings_via_rest(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_finding("SSH-001", "ssh", "critical")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    body = resp.json()
    ssh_score = next(c for c in body["score"]["category_scores"] if c["category"] == "ssh")
    assert ssh_score["score"] == 75.0
    assert body["score"]["overall_score"] < 100.0


# ── REST and MCP return identical scores ─────────────────────────────────────


def test_rest_and_mcp_scores_are_identical(client, auth_headers, db_engine, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_finding("DOCKER-006", "docker", "high")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    rest_resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    rest_body = rest_resp.json()

    test_session = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.mcp.tools._common.SessionLocal", test_session)
    from app.mcp.tools import get_security_score

    mcp_body = get_security_score.get_security_score(server_id)

    assert rest_body["score"]["overall_score"] == mcp_body["score"]["overall_score"]
    assert rest_body["total_checks"] == mcp_body["total_checks"]
    assert rest_body["baseline_version"] == mcp_body["baseline_version"]


# ── Scan ingestion never fails even if scoring would error ──────────────────


def test_scan_ingestion_succeeds_even_if_scoring_raises(client, auth_headers, monkeypatch):
    """Scoring failures must never break scan ingestion — the scan itself
    is the primary artifact and must be durably saved regardless."""
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated scoring failure")

    monkeypatch.setattr("app.services.scoring_service.compute_security_score", _boom)

    resp = client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 202  # scan itself still succeeds

    # Score is simply unavailable, not a 500 error.
    score_resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    assert score_resp.status_code == 200
    assert score_resp.json()["available"] is False


# ── Baseline sync integration ─────────────────────────────────────────────────


def test_baseline_sync_then_get_effective_rules(db_session):
    from app.services.baseline_engine_service import get_effective_rules, sync_baselines_to_db

    sync_baselines_to_db(db_session, distros=("ubuntu",))
    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert "PermitRootLogin" in rules


def test_custom_override_affects_get_effective_rules_after_sync(db_session):
    from app.services.baseline_engine_service import (
        get_effective_rules,
        set_custom_rule_override,
        sync_baselines_to_db,
    )

    sync_baselines_to_db(db_session, distros=("ubuntu",))
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "MaxAuthTries", {"expected": "2", "severity": "medium"}
    )

    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert rules["MaxAuthTries"]["expected"] == "2"
    # YAML-synced rules for other keys remain
    assert "PermitRootLogin" in rules
