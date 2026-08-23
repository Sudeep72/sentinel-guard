from datetime import UTC, datetime, timedelta


def _registration_body(hostname="web01"):
    return {
        "hostname": hostname,
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _finding_body(check_id="PERM-001", module="permission", severity="critical"):
    return {
        "check_id": check_id,
        "module": module,
        "title": f"Finding {check_id}",
        "severity": severity,
        "description": "description",
        "why_it_matters": "why it matters",
        "attack_scenario": "attack scenario",
        "recommendation": "recommendation",
    }


def _scan_body(server_id, findings):
    now = datetime.now(UTC)
    return {
        "server_id": server_id,
        "hostname": "web01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "completed_at": now.isoformat(),
        "status": "completed",
        "guardian_results": [
            {
                "module": "permission",
                "status": "ok",
                "findings": findings,
                "collected_at": now.isoformat(),
            }
        ],
    }


def _seed_findings(client, findings):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]
    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id, findings),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return server_id


def test_list_findings_requires_auth(client):
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 401


def test_list_findings_empty(client, auth_headers):
    resp = client.get("/api/v1/findings", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_findings_returns_seeded_findings(client, auth_headers):
    _seed_findings(client, [_finding_body("PERM-001"), _finding_body("SSH-001", "ssh", "high")])

    resp = client.get("/api/v1/findings", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_list_findings_filter_by_severity(client, auth_headers):
    _seed_findings(
        client,
        [_finding_body("PERM-001", severity="critical"), _finding_body("SSH-001", "ssh", "low")],
    )

    resp = client.get("/api/v1/findings?severity=critical", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["check_id"] == "PERM-001"


def test_list_findings_filter_by_category(client, auth_headers):
    _seed_findings(client, [_finding_body("PERM-001"), _finding_body("SSH-001", "ssh")])

    resp = client.get("/api/v1/findings?category=ssh", headers=auth_headers)
    assert len(resp.json()) == 1
    assert resp.json()[0]["module"] == "ssh"


def test_list_findings_filter_by_status(client, auth_headers):
    _seed_findings(client, [_finding_body("PERM-001")])

    open_resp = client.get("/api/v1/findings?status=open", headers=auth_headers)
    resolved_resp = client.get("/api/v1/findings?status=resolved", headers=auth_headers)
    assert len(open_resp.json()) == 1
    assert len(resolved_resp.json()) == 0


def test_get_finding_detail(client, auth_headers):
    _seed_findings(client, [_finding_body("PERM-001")])
    finding_id = client.get("/api/v1/findings", headers=auth_headers).json()[0]["id"]

    resp = client.get(f"/api/v1/findings/{finding_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["check_id"] == "PERM-001"
    assert resp.json()["why_it_matters"] == "why it matters"


def test_get_finding_detail_not_found(client, auth_headers):
    resp = client.get("/api/v1/findings/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404
