from datetime import UTC, datetime, timedelta


def _registration_body(hostname="web01"):
    return {
        "hostname": hostname,
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _scan_body(server_id):
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
        "guardian_results": [],
    }


def _register_and_scan(client):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]
    client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return server_id


def test_get_report_requires_auth(client):
    resp = client.get("/api/v1/servers/some-id/report")
    assert resp.status_code == 401


def test_get_report_server_not_found(client, auth_headers):
    resp = client.get("/api/v1/servers/nonexistent-id/report", headers=auth_headers)
    assert resp.status_code == 404


def test_get_report_no_scans_yet(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    server_id = reg.json()["server"]["id"]

    resp = client.get(f"/api/v1/servers/{server_id}/report", headers=auth_headers)
    assert resp.status_code == 404


def test_get_report_default_format_is_executive(client, auth_headers):
    server_id = _register_and_scan(client)
    resp = client.get(f"/api/v1/servers/{server_id}/report", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["format"] == "executive"


def test_get_report_json_format(client, auth_headers):
    server_id = _register_and_scan(client)
    resp = client.get(f"/api/v1/servers/{server_id}/report?format=json", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["format"] == "json"


def test_get_report_markdown_format(client, auth_headers):
    server_id = _register_and_scan(client)
    resp = client.get(f"/api/v1/servers/{server_id}/report?format=markdown", headers=auth_headers)
    assert resp.status_code == 200
    assert "# SentinelGuard Technical Report" in resp.json()["content"]


def test_get_report_invalid_format_rejected(client, auth_headers):
    server_id = _register_and_scan(client)
    resp = client.get(f"/api/v1/servers/{server_id}/report?format=pdf", headers=auth_headers)
    assert resp.status_code == 422
