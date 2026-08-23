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


def test_get_score_requires_auth(client):
    resp = client.get("/api/v1/servers/some-id/score")
    assert resp.status_code == 401


def test_get_score_server_not_found(client, auth_headers):
    resp = client.get("/api/v1/servers/nonexistent-id/score", headers=auth_headers)
    assert resp.status_code == 404


def test_get_score_no_scans_yet(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    server_id = reg.json()["server"]["id"]

    resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    assert resp.status_code == 404


def test_get_score_available_immediately_after_scan(client, auth_headers):
    server_id = _register_and_scan(client)

    resp = client.get(f"/api/v1/servers/{server_id}/score", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is True
    assert body["score"]["overall_score"] == 100.0
    assert body["total_checks"] is not None
    assert body["baseline_version"] == "1.0.0"


def test_get_baseline_requires_auth(client):
    resp = client.get("/api/v1/servers/some-id/baseline")
    assert resp.status_code == 401


def test_get_baseline_server_not_found(client, auth_headers):
    resp = client.get("/api/v1/servers/nonexistent-id/baseline", headers=auth_headers)
    assert resp.status_code == 404


def test_get_baseline_not_yet_available(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    server_id = reg.json()["server"]["id"]
    # No scan submitted yet — baseline returns not-available (no scans message)
    resp = client.get(f"/api/v1/servers/{server_id}/baseline", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
