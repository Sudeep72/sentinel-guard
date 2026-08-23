"""Integration tests for 3B Guardian findings through the full REST and MCP stack."""

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
    Severity,
)

from app.modules.cron.analyzer import CronAnalyzer
from app.modules.registry import clear_registry, register_analyzer
from app.modules.secret.analyzer import SecretAnalyzer
from app.modules.sudo.analyzer import SudoAnalyzer


@pytest.fixture(autouse=True)
def _register():
    clear_registry()
    register_analyzer(SudoAnalyzer())
    register_analyzer(CronAnalyzer())
    register_analyzer(SecretAnalyzer())
    yield
    clear_registry()


def _reg_body():
    return {
        "hostname": "srv01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _sudo_finding(check_id: str = "SUDO-003") -> dict:
    return {
        "check_id": check_id,
        "module": "sudo",
        "title": f"Sudo issue {check_id}",
        "severity": "high",
        "description": "sudo misconfiguration",
        "why_it_matters": "privilege escalation",
        "attack_scenario": "attacker uses sudo",
        "recommendation": "fix sudoers",
        "current_value": "alice ALL=(ALL) NOPASSWD: ALL",
        "expected_value": "no NOPASSWD",
    }


def _cron_finding(check_id: str = "CRON-002") -> dict:
    return {
        "check_id": check_id,
        "module": "cron",
        "title": f"Cron issue {check_id}",
        "severity": "high",
        "description": "world-writable cron file",
        "why_it_matters": "root code injection",
        "attack_scenario": "attacker writes to cron",
        "recommendation": "chmod o-w /etc/cron.d/backup",
        "current_value": "0o777",
        "expected_value": "not world-writable",
    }


def _secret_finding(check_id: str = "SECRET-001") -> dict:
    return {
        "check_id": check_id,
        "module": "secret",
        "title": f"Secret issue {check_id}",
        "severity": "high",
        "description": "SSH private key exposed",
        "why_it_matters": "credential theft",
        "attack_scenario": "attacker reads key",
        "recommendation": "chmod 600 key && rotate",
        "current_value": "unencrypted key at mode=0o644",
        "expected_value": "mode 600, owner-only access",
    }


def _scan_body(server_id: str, findings: list[dict]) -> dict:
    now = datetime.now(UTC)
    return {
        "server_id": server_id,
        "hostname": "srv01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "completed_at": now.isoformat(),
        "status": "completed",
        "guardian_results": [
            {
                "module": findings[0]["module"],
                "status": "ok",
                "findings": findings,
                "collected_at": now.isoformat(),
            }
        ],
    }


# ── REST API integration ──────────────────────────────────────────────────────


def test_sudo_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_sudo_finding("SUDO-003")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    findings_resp = client.get("/api/v1/findings?category=sudo", headers=auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "SUDO-003"
    assert findings[0]["module"] == "sudo"


def test_cron_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_cron_finding("CRON-002")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    findings_resp = client.get("/api/v1/findings?category=cron", headers=auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "CRON-002"


def test_secret_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_secret_finding("SECRET-001")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    findings_resp = client.get(
        "/api/v1/findings?category=secret&severity=high",
        headers=auth_headers,
    )
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "SECRET-001"


def test_baseline_comparison_includes_3b_categories(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]
    now = datetime.now(UTC)

    client.post(
        "/api/v1/agents/scans",
        json={
            "server_id": server_id,
            "hostname": "srv01",
            "distro": "ubuntu",
            "distro_version": "24.04",
            "agent_version": "0.1.0",
            "started_at": (now - timedelta(seconds=5)).isoformat(),
            "completed_at": now.isoformat(),
            "status": "completed",
            "guardian_results": [],
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )

    for category in ("sudo", "cron", "secret"):
        resp = client.get(
            f"/api/v1/servers/{server_id}/baseline?category={category}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True, f"Baseline not available for {category}"
        assert len(body["comparisons"]) > 0
        for item in body["comparisons"]:
            assert item["category"] == category


def test_explain_finding_includes_copilot_payload(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_sudo_finding("SUDO-004")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    finding_id = findings[0]["id"]

    detail_resp = client.get(f"/api/v1/findings/{finding_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["why_it_matters"]
    assert detail["attack_scenario"]
    assert detail["recommendation"]


def test_report_includes_3b_findings(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_secret_finding("SECRET-003")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get(
        f"/api/v1/servers/{server_id}/report?format=markdown",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    content = resp.json()["content"]
    assert "SECRET-003" in content


# ── MCP tool integration ──────────────────────────────────────────────────────


@pytest.fixture()
def _patch_mcp_session(monkeypatch, db_engine):
    from sqlalchemy.orm import sessionmaker

    test_session = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.mcp.tools._common.SessionLocal", test_session)


def test_mcp_list_findings_returns_sudo_findings(db_session, _patch_mcp_session):
    from sentinelguard_contracts import ServerRegistration

    from app.mcp.tools import list_findings
    from app.services.scan_service import ingest_scan
    from app.services.server_service import get_server_orm_or_none, register_server

    reg = ServerRegistration(
        hostname="srv01", distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, reg)
    server = get_server_orm_or_none(db_session, info.id)

    now = datetime.now(UTC)
    finding = Finding(
        check_id="SUDO-003",
        module=GuardianCategory.SUDO,
        title="NOPASSWD rule",
        severity=Severity.HIGH,
        description="desc",
        why_it_matters="matters",
        attack_scenario="scenario",
        recommendation="fix",
        current_value="alice ALL=(ALL) NOPASSWD: ALL",
        expected_value="no NOPASSWD",
    )
    payload = ScanPayload(
        server_id=server.id,
        hostname="srv01",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=now - timedelta(seconds=5),
        completed_at=now,
        status=ScanStatus.COMPLETED,
        guardian_results=[
            GuardianResult(
                module=GuardianCategory.SUDO,
                status=GuardianRunStatus.OK,
                findings=[finding],
                collected_at=now,
            )
        ],
    )
    ingest_scan(db_session, server, payload)

    result = list_findings.list_findings(category="sudo")
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "SUDO-003"


def test_mcp_compare_to_baseline_returns_3b_categories(db_session, _patch_mcp_session):
    from sentinelguard_contracts import ServerRegistration

    from app.mcp.tools import compare_to_baseline
    from app.services.scan_service import ingest_scan
    from app.services.server_service import get_server_orm_or_none, register_server

    reg = ServerRegistration(
        hostname="srv01", distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, reg)
    server = get_server_orm_or_none(db_session, info.id)

    now = datetime.now(UTC)
    ingest_scan(
        db_session,
        server,
        ScanPayload(
            server_id=server.id,
            hostname="srv01",
            distro=Distro.UBUNTU,
            distro_version="24.04",
            agent_version="0.1.0",
            started_at=now - timedelta(seconds=5),
            completed_at=now,
            status=ScanStatus.COMPLETED,
            guardian_results=[],
        ),
    )

    result = compare_to_baseline.compare_to_baseline(server.id, category="sudo")
    assert result["available"] is True
    comparisons = result["comparisons"]
    assert len(comparisons) > 0
    assert all(c["category"] == "sudo" for c in comparisons)
