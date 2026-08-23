def _registration_body(hostname="web01"):
    return {
        "hostname": hostname,
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def test_list_servers_requires_auth(client):
    resp = client.get("/api/v1/servers")
    assert resp.status_code == 401


def test_list_servers_empty_fleet(client, auth_headers):
    resp = client.get("/api/v1/servers", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_servers_returns_registered_fleet(client, auth_headers):
    client.post("/api/v1/agents/register", json=_registration_body("web01"))
    client.post("/api/v1/agents/register", json=_registration_body("api01"))

    resp = client.get("/api/v1/servers", headers=auth_headers)
    assert resp.status_code == 200
    hostnames = {s["hostname"] for s in resp.json()}
    assert hostnames == {"web01", "api01"}


def test_get_server_detail(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    server_id = reg.json()["server"]["id"]

    resp = client.get(f"/api/v1/servers/{server_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["hostname"] == "web01"


def test_get_server_detail_not_found(client, auth_headers):
    resp = client.get("/api/v1/servers/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


def test_get_server_scans_empty(client, auth_headers):
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    server_id = reg.json()["server"]["id"]

    resp = client.get(f"/api/v1/servers/{server_id}/scans", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_server_scans_not_found_server(client, auth_headers):
    resp = client.get("/api/v1/servers/nonexistent-id/scans", headers=auth_headers)
    assert resp.status_code == 404


def test_viewer_can_list_servers(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    resp = client.get("/api/v1/servers", headers=headers)
    assert resp.status_code == 200
