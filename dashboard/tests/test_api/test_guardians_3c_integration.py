"""Integration tests for Docker, Firewall, Kernel Guardians through the full stack."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.modules.docker.analyzer import DockerAnalyzer
from app.modules.firewall.analyzer import FirewallAnalyzer
from app.modules.kernel.analyzer import KernelAnalyzer
from app.modules.registry import clear_registry, register_analyzer


@pytest.fixture(autouse=True)
def _register():
    clear_registry()
    register_analyzer(DockerAnalyzer())
    register_analyzer(FirewallAnalyzer())
    register_analyzer(KernelAnalyzer())
    yield
    clear_registry()


def _reg_body():
    return {
        "hostname": "srv01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _docker_finding(check_id="DOCKER-006"):
    return {
        "check_id": check_id,
        "module": "docker",
        "title": f"Docker issue {check_id}",
        "severity": "critical",
        "description": "privileged container",
        "why_it_matters": "host compromise",
        "attack_scenario": "attacker escapes container",
        "recommendation": "remove --privileged",
        "current_value": "privileged=true",
        "expected_value": "privileged=false",
    }


def _firewall_finding(check_id="FIREWALL-001"):
    return {
        "check_id": check_id,
        "module": "firewall",
        "title": f"Firewall issue {check_id}",
        "severity": "critical",
        "description": "no firewall active",
        "why_it_matters": "unrestricted access",
        "attack_scenario": "attacker connects directly",
        "recommendation": "enable ufw",
        "current_value": "no firewall active",
        "expected_value": "active firewall",
    }


def _kernel_finding(check_id="KERNEL-001"):
    return {
        "check_id": check_id,
        "module": "kernel",
        "title": f"Kernel issue {check_id}",
        "severity": "high",
        "description": "ASLR disabled",
        "why_it_matters": "memory exploit protection lost",
        "attack_scenario": "predictable memory addresses",
        "recommendation": "sysctl -w kernel.randomize_va_space=2",
        "current_value": "0",
        "expected_value": "2",
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


def test_docker_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_docker_finding("DOCKER-006")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get("/api/v1/findings?category=docker", headers=auth_headers)
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "DOCKER-006"


def test_firewall_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_firewall_finding("FIREWALL-001")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get("/api/v1/findings?category=firewall", headers=auth_headers)
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "FIREWALL-001"


def test_kernel_findings_stored_and_retrievable(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_kernel_finding("KERNEL-007")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get("/api/v1/findings?category=kernel&severity=high", headers=auth_headers)
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["check_id"] == "KERNEL-007"


def test_baseline_comparison_includes_3c_categories(client, auth_headers):
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

    for category in ("docker", "firewall", "kernel"):
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


def test_report_includes_3c_findings(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_reg_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, [_kernel_finding("KERNEL-013")]),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    resp = client.get(f"/api/v1/servers/{server_id}/report?format=markdown", headers=auth_headers)
    assert resp.status_code == 200
    assert "KERNEL-013" in resp.json()["content"]


def test_all_nine_categories_supported_in_findings_filter(client, auth_headers):
    """Sanity check: filtering by every one of the nine Guardian categories works."""
    categories = [
        "permission",
        "ownership",
        "ssh",
        "sudo",
        "cron",
        "secret",
        "docker",
        "firewall",
        "kernel",
    ]
    for category in categories:
        resp = client.get(f"/api/v1/findings?category={category}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []  # no findings yet, but no error


# ── MCP tool integration ──────────────────────────────────────────────────────


@pytest.fixture()
def _patch_mcp_session(monkeypatch, db_engine):
    from sqlalchemy.orm import sessionmaker

    test_session = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.mcp.tools._common.SessionLocal", test_session)


def test_mcp_list_findings_returns_docker_findings(db_session, _patch_mcp_session):
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
        check_id="DOCKER-006",
        module=GuardianCategory.DOCKER,
        title="Privileged container",
        severity=Severity.CRITICAL,
        description="desc",
        why_it_matters="matters",
        attack_scenario="scenario",
        recommendation="fix",
        current_value="privileged=true",
        expected_value="privileged=false",
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
                module=GuardianCategory.DOCKER,
                status=GuardianRunStatus.OK,
                findings=[finding],
                collected_at=now,
            )
        ],
    )
    ingest_scan(db_session, server, payload)

    result = list_findings.list_findings(category="docker")
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "DOCKER-006"


def test_mcp_compare_to_baseline_returns_3c_categories(db_session, _patch_mcp_session):
    from sentinelguard_contracts import Distro, ScanPayload, ScanStatus, ServerRegistration

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

    for category in ("docker", "firewall", "kernel"):
        result = compare_to_baseline.compare_to_baseline(server.id, category=category)
        assert result["available"] is True
        assert len(result["comparisons"]) > 0
        assert all(c["category"] == category for c in result["comparisons"])


def test_mcp_health_and_list_servers_still_work(db_session, _patch_mcp_session):
    """Sanity check that unrelated MCP tools are unaffected by 3C additions."""
    from app.mcp.tools import health, list_servers

    health_result = health.health()
    assert health_result["status"] == "ok"

    servers_result = list_servers.list_servers()
    assert "servers" in servers_result
