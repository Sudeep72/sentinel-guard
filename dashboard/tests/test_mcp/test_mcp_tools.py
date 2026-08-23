"""MCP tool tests.

These call the tool functions directly (they're plain Python callables —
see app/mcp/server.py's docstring on why they're registered rather than
decorated in place) against a monkeypatched DB session, proving each
tool produces output consistent with its underlying service function.
"""

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

from app.mcp.tools import (
    compare_to_baseline,
    explain_finding,
    generate_report,
    get_security_score,
    health,
    list_findings,
    list_servers,
    scan_server,
)
from app.services.scan_service import ingest_scan
from app.services.server_service import get_server_orm_or_none, register_server


@pytest.fixture(autouse=True)
def _patch_mcp_session(monkeypatch, db_engine):
    """Point every MCP tool's db_session() helper at the test's in-memory engine."""
    from sqlalchemy.orm import sessionmaker

    test_session_local = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.mcp.tools._common.SessionLocal", test_session_local)


def _server(db_session, hostname="web01"):
    registration = ServerRegistration(
        hostname=hostname, distro=Distro.UBUNTU, distro_version="24.04", agent_version="0.1.0"
    )
    info, _ = register_server(db_session, registration)
    return get_server_orm_or_none(db_session, info.id)


def _finding(check_id="PERM-001") -> Finding:
    return Finding(
        check_id=check_id,
        module=GuardianCategory.PERMISSION,
        title="/etc/shadow is world-readable",
        severity=Severity.CRITICAL,
        description="/etc/shadow has mode 644.",
        why_it_matters="Password hashes become readable.",
        attack_scenario="Offline cracking becomes possible.",
        recommendation="chmod 600 /etc/shadow",
    )


def _scan(db_session, server, findings=None):
    now = datetime.now(UTC)
    guardian_results = []
    if findings is not None:
        guardian_results.append(
            GuardianResult(
                module=GuardianCategory.PERMISSION,
                status=GuardianRunStatus.OK,
                findings=findings,
                collected_at=now,
            )
        )
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


def test_health_tool(db_session):
    result = health.health()
    assert result["status"] == "ok"
    assert result["database"] == "ok"


def test_list_servers_tool_empty(db_session):
    result = list_servers.list_servers()
    assert result == {"servers": []}


def test_list_servers_tool_returns_fleet(db_session):
    _server(db_session, "web01")
    _server(db_session, "web02")

    result = list_servers.list_servers()
    hostnames = {s["hostname"] for s in result["servers"]}
    assert hostnames == {"web01", "web02"}


def test_scan_server_tool_no_scans_yet(db_session):
    server = _server(db_session)
    result = scan_server.scan_server(server.id)
    assert result["available"] is False
    assert "on-demand remote triggering" in result["message"]


def test_scan_server_tool_unknown_server(db_session):
    result = scan_server.scan_server("nonexistent-id")
    assert result["available"] is False


def test_scan_server_tool_returns_latest_scan(db_session):
    server = _server(db_session)
    scan = _scan(db_session, server)

    result = scan_server.scan_server(server.id)
    assert result["available"] is True
    assert result["scan"]["id"] == scan.id


def test_get_security_score_tool_available_after_scan(db_session):
    server = _server(db_session)
    _scan(db_session, server)

    result = get_security_score.get_security_score(server.id)
    assert result["available"] is True
    assert result["score"]["overall_score"] == 100.0


def test_get_security_score_tool_unknown_server(db_session):
    result = get_security_score.get_security_score("nonexistent-id")
    assert result["available"] is False


def test_list_findings_tool_returns_seeded_findings(db_session):
    server = _server(db_session)
    _scan(db_session, server, findings=[_finding()])

    result = list_findings.list_findings()
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "PERM-001"


def test_list_findings_tool_filters_by_server(db_session):
    server1 = _server(db_session, "web01")
    server2 = _server(db_session, "web02")
    _scan(db_session, server1, findings=[_finding("PERM-001")])
    _scan(db_session, server2, findings=[_finding("SSH-001")])

    result = list_findings.list_findings(server_id=server1.id)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "PERM-001"


def test_explain_finding_tool_found(db_session):
    server = _server(db_session)
    _scan(db_session, server, findings=[_finding()])
    finding_id = list_findings.list_findings()["findings"][0]["id"]

    result = explain_finding.explain_finding(finding_id)
    assert result["available"] is True
    assert result["finding"]["check_id"] == "PERM-001"


def test_explain_finding_tool_not_found(db_session):
    result = explain_finding.explain_finding("nonexistent-id")
    assert result["available"] is False


def test_compare_to_baseline_tool_not_available(db_session):
    server = _server(db_session)
    # No scan yet — compare should return not-available
    result = compare_to_baseline.compare_to_baseline(server.id)
    assert result["available"] is False


def test_compare_to_baseline_tool_unknown_server(db_session):
    result = compare_to_baseline.compare_to_baseline("nonexistent-id")
    assert result["available"] is False


def test_generate_report_tool_success(db_session):
    server = _server(db_session)
    _scan(db_session, server, findings=[_finding()])

    result = generate_report.generate_report(server.id, format="markdown")
    assert result["available"] is True
    assert "chmod 600 /etc/shadow" in result["report"]["content"]


def test_generate_report_tool_invalid_format(db_session):
    server = _server(db_session)
    _scan(db_session, server)

    result = generate_report.generate_report(server.id, format="pdf")
    assert result["available"] is False
    assert "Unknown format" in result["message"]


def test_generate_report_tool_unknown_server(db_session):
    result = generate_report.generate_report("nonexistent-id", format="json")
    assert result["available"] is False
