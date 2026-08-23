def test_health_endpoint_smoke(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_health_endpoint_requires_no_auth(client):
    # No Authorization header supplied — should still succeed.
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
