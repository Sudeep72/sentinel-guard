from datetime import UTC, datetime, timedelta


def _registration_body(hostname="web01"):
    return {
        "hostname": hostname,
        "ip_address": "10.0.0.5",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def _scan_body(server_id=None, status="completed", findings=None):
    now = datetime.now(UTC)
    guardian_results = []
    if findings is not None:
        guardian_results.append(
            {
                "module": "permission",
                "status": "ok",
                "findings": findings,
                "collected_at": now.isoformat(),
            }
        )
    return {
        "server_id": server_id,
        "hostname": "web01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "completed_at": now.isoformat(),
        "status": status,
        "guardian_results": guardian_results,
    }


def _finding_body(check_id="PERM-001"):
    return {
        "check_id": check_id,
        "module": "permission",
        "title": "/etc/shadow is world-readable",
        "severity": "critical",
        "description": "/etc/shadow has mode 644.",
        "why_it_matters": "Password hashes become readable.",
        "attack_scenario": "Offline cracking becomes possible.",
        "recommendation": "chmod 600 /etc/shadow",
        "current_value": "644",
        "expected_value": "600",
    }


def test_register_agent_no_auth_required(client):
    resp = client.post("/api/v1/agents/register", json=_registration_body())
    assert resp.status_code == 201
    body = resp.json()
    assert body["server"]["hostname"] == "web01"
    assert body["server"]["status"] == "online"
    assert len(body["api_key"]) > 32


def test_register_two_agents_get_different_keys(client):
    resp1 = client.post("/api/v1/agents/register", json=_registration_body("web01"))
    resp2 = client.post("/api/v1/agents/register", json=_registration_body("web02"))
    assert resp1.json()["api_key"] != resp2.json()["api_key"]
    assert resp1.json()["server"]["id"] != resp2.json()["server"]["id"]


def test_submit_scan_requires_api_key(client):
    resp = client.post("/api/v1/agents/scans", json=_scan_body())
    assert resp.status_code == 401


def test_submit_scan_rejects_bad_api_key(client):
    resp = client.post(
        "/api/v1/agents/scans",
        json=_scan_body(),
        headers={"Authorization": "Bearer not-a-real-key"},
    )
    assert resp.status_code == 401


def test_submit_scan_success(client):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]

    resp = client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id=server_id, findings=[_finding_body()]),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "accepted"
    assert "scan_id" in body


def test_submit_scan_attributed_to_key_owner_not_payload_claim(client):
    reg1 = client.post("/api/v1/agents/register", json=_registration_body("web01"))
    reg2 = client.post("/api/v1/agents/register", json=_registration_body("web02"))
    api_key1 = reg1.json()["api_key"]
    server2_id = reg2.json()["server"]["id"]

    # Authenticate as server1's key, but claim server2's id in the payload.
    resp = client.post(
        "/api/v1/agents/scans",
        json=_scan_body(server_id=server2_id),
        headers={"Authorization": f"Bearer {api_key1}"},
    )
    assert resp.status_code == 202

    # Verify (via admin) the scan landed on server1, not server2.
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    token = client.post(
        "/api/v1/auth/token", data={"username": "admin@example.com", "password": "adminpass123"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    server1_id = reg1.json()["server"]["id"]
    scans_server1 = client.get(f"/api/v1/servers/{server1_id}/scans", headers=headers).json()
    scans_server2 = client.get(f"/api/v1/servers/{server2_id}/scans", headers=headers).json()

    assert len(scans_server1) == 1
    assert len(scans_server2) == 0


def test_register_agent_invalid_distro_rejected(client):
    body = _registration_body()
    body["distro"] = "windows"
    resp = client.post("/api/v1/agents/register", json=body)
    assert resp.status_code == 422


def test_submit_scan_invalid_payload_rejected(client):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    api_key = reg.json()["api_key"]
    resp = client.post(
        "/api/v1/agents/scans",
        json={"not": "a valid scan payload"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 422


def test_reregistering_same_hostname_via_rest_does_not_duplicate(client, auth_headers):
    resp1 = client.post("/api/v1/agents/register", json=_registration_body("kali"))
    resp2 = client.post("/api/v1/agents/register", json=_registration_body("kali"))

    assert resp1.json()["server"]["id"] == resp2.json()["server"]["id"]
    assert resp1.json()["api_key"] != resp2.json()["api_key"]

    servers = client.get("/api/v1/servers", headers=auth_headers).json()
    assert sum(1 for s in servers if s["hostname"] == "kali") == 1
