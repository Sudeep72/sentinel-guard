"""End-to-end lifecycle integration test (Phase 21 release validation).

Exercises the complete SentinelGuard flow in one continuous scenario,
through the real FastAPI application (routing, auth, serialization,
database, services -- the same code path a real HTTP request takes,
via Starlette's ASGI TestClient transport rather than a live TCP
socket):

    fresh install -> admin bootstrap -> agent registration ->
    scan submission (multi-Guardian, multi-severity) ->
    automatic scoring -> baseline comparison -> all 4 report formats ->
    MCP tool parity -> multi-server fleet isolation

This is the release-readiness smoke test: if this fails, the release
is not ready, regardless of what the unit test suites say in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def test_full_v1_lifecycle(client, db_engine, monkeypatch):
    """One continuous scenario covering every major v1.0 capability."""

    # -- 1. Fresh install: health check with no auth --
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    # -- 2. Bootstrap: first user auto-becomes admin --
    register = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@sentinelguard.example.com",
            "password": "ChangeMe123!",
            "role": "viewer",
        },
    )
    assert register.status_code == 201
    assert register.json()["role"] == "admin"  # bootstrap override

    token_resp = client.post(
        "/api/v1/auth/token",
        data={"username": "admin@sentinelguard.example.com", "password": "ChangeMe123!"},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # -- 3. Agent registration (two servers, proving fleet support) --
    reg1 = client.post(
        "/api/v1/agents/register",
        json={
            "hostname": "prod-web-01",
            "ip_address": "10.0.1.5",
            "distro": "ubuntu",
            "distro_version": "24.04",
            "agent_version": "1.0.0",
        },
    )
    assert reg1.status_code == 201
    server1_id = reg1.json()["server"]["id"]
    server1_key = reg1.json()["api_key"]

    reg2 = client.post(
        "/api/v1/agents/register",
        json={
            "hostname": "prod-db-01",
            "distro": "rocky",
            "distro_version": "9.4",
            "agent_version": "1.0.0",
        },
    )
    assert reg2.status_code == 201
    server2_id = reg2.json()["server"]["id"]
    server2_key = reg2.json()["api_key"]

    fleet = client.get("/api/v1/servers", headers=headers)
    assert fleet.status_code == 200
    assert len(fleet.json()) == 2

    # -- 4. Scan submission: realistic multi-Guardian, multi-severity --
    now = _now_iso()
    scan_payload = {
        "server_id": server1_id,
        "hostname": "prod-web-01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "1.0.0",
        "started_at": (datetime.now(UTC) - timedelta(seconds=8)).isoformat(),
        "completed_at": now,
        "status": "completed",
        "guardian_results": [
            {
                "module": "ssh",
                "status": "ok",
                "collected_at": now,
                "findings": [
                    {
                        "check_id": "SSH-001",
                        "module": "ssh",
                        "title": "SSH root login is permitted",
                        "severity": "high",
                        "description": "PermitRootLogin is set to yes.",
                        "why_it_matters": "Eliminates the audit trail from su/sudo.",
                        "attack_scenario": "Attacker with leaked root password gets a shell.",
                        "recommendation": "Set PermitRootLogin no.",
                        "current_value": "yes",
                        "expected_value": "no",
                    }
                ],
            },
            {
                "module": "secret",
                "status": "ok",
                "collected_at": now,
                "findings": [
                    {
                        "check_id": "SECRET-001",
                        "module": "secret",
                        "title": "SSH private key file exposed",
                        "severity": "critical",
                        "description": "Unencrypted key at /root/.ssh/id_rsa.",
                        "why_it_matters": "Anyone with read access can authenticate as root.",
                        "attack_scenario": "Attacker copies the key and authenticates elsewhere.",
                        "recommendation": "chmod 600, rotate the key.",
                        "current_value": "mode=0644",
                        "expected_value": "mode=0600",
                    }
                ],
            },
            {
                "module": "kernel",
                "status": "ok",
                "collected_at": now,
                "findings": [
                    {
                        "check_id": "KERNEL-001",
                        "module": "kernel",
                        "title": "ASLR is not fully enabled",
                        "severity": "low",
                        "description": "kernel.randomize_va_space=1",
                        "why_it_matters": "Reduces exploit mitigation effectiveness.",
                        "attack_scenario": "Predictable memory layout aids overflow exploits.",
                        "recommendation": "sysctl -w kernel.randomize_va_space=2",
                        "current_value": "1",
                        "expected_value": "2",
                    }
                ],
            },
        ],
    }
    scan_resp = client.post(
        "/api/v1/agents/scans",
        json=scan_payload,
        headers={"Authorization": f"Bearer {server1_key}"},
    )
    assert scan_resp.status_code == 202

    # Second server: clean scan, no findings -- proves per-server isolation.
    clean_payload = dict(scan_payload)
    clean_payload["server_id"] = server2_id
    clean_payload["hostname"] = "prod-db-01"
    clean_payload["distro"] = "rocky"
    clean_payload["distro_version"] = "9.4"
    clean_payload["guardian_results"] = []
    clean_scan = client.post(
        "/api/v1/agents/scans",
        json=clean_payload,
        headers={"Authorization": f"Bearer {server2_key}"},
    )
    assert clean_scan.status_code == 202

    # -- 5. Findings retrievable, correctly attributed --
    all_findings = client.get("/api/v1/findings", headers=headers).json()
    assert len(all_findings) == 3  # only server1's findings

    server1_findings = client.get(
        f"/api/v1/findings?server_id={server1_id}", headers=headers
    ).json()
    assert len(server1_findings) == 3

    server2_findings = client.get(
        f"/api/v1/findings?server_id={server2_id}", headers=headers
    ).json()
    assert len(server2_findings) == 0  # clean scan, correctly isolated

    critical_findings = client.get("/api/v1/findings?severity=critical", headers=headers).json()
    assert len(critical_findings) == 1
    assert critical_findings[0]["check_id"] == "SECRET-001"

    # -- 6. Baseline comparison --
    baseline = client.get(f"/api/v1/servers/{server1_id}/baseline", headers=headers)
    assert baseline.status_code == 200
    assert baseline.json()["available"] is True
    assert len(baseline.json()["comparisons"]) > 0

    # -- 7. Score computed automatically (Phase 18) --
    score = client.get(f"/api/v1/servers/{server1_id}/score", headers=headers)
    assert score.status_code == 200
    score_body = score.json()
    assert score_body["available"] is True
    assert score_body["score"]["overall_score"] < 100.0
    assert len(score_body["score"]["category_scores"]) == 9
    assert score_body["baseline_version"] == "1.0.0"

    clean_score = client.get(f"/api/v1/servers/{server2_id}/score", headers=headers)
    assert clean_score.json()["score"]["overall_score"] == 100.0  # clean server unaffected

    # -- 8. All four report formats generate successfully --
    for fmt in ("executive", "technical", "markdown", "json"):
        report = client.get(f"/api/v1/servers/{server1_id}/report?format={fmt}", headers=headers)
        assert report.status_code == 200
        assert len(report.json()["content"]) > 0

    exec_report = client.get(
        f"/api/v1/servers/{server1_id}/report?format=executive", headers=headers
    ).json()
    assert "Attack scenario" not in exec_report["content"]

    tech_report = client.get(
        f"/api/v1/servers/{server1_id}/report?format=technical", headers=headers
    ).json()
    assert "Attack scenario" in tech_report["content"]
    assert "SECRET-001" in tech_report["content"]

    # -- 9. MCP tools return results identical to REST (same service layer) --
    from sqlalchemy.orm import sessionmaker

    test_session = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.mcp.tools._common.SessionLocal", test_session)

    from app.mcp.tools import (
        compare_to_baseline,
        get_security_score,
        health,
        list_findings,
        list_servers,
    )

    mcp_health = health.health()
    assert mcp_health["status"] == "ok"

    mcp_servers = list_servers.list_servers()
    assert len(mcp_servers["servers"]) == 2

    mcp_findings = list_findings.list_findings(server_id=server1_id)
    assert len(mcp_findings["findings"]) == 3

    mcp_score = get_security_score.get_security_score(server1_id)
    assert mcp_score["score"]["overall_score"] == score_body["score"]["overall_score"]

    mcp_baseline = compare_to_baseline.compare_to_baseline(server1_id)
    assert mcp_baseline["available"] is True
