"""Coverage for auth dependency edge cases."""

from datetime import UTC, datetime, timedelta


def _registration_body(hostname="web01"):
    return {
        "hostname": hostname,
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
    }


def test_require_admin_rejects_viewer(client, viewer_token):
    """Covers the require_admin 403 branch in dependencies.py."""
    # create a second user as viewer — requires admin token first
    client.post(
        "/api/v1/auth/register",
        json={"email": "adm@x.com", "password": "adminpass123", "role": "admin"},
    )
    # viewer_token fixture user already exists via fixture; just hit admin-only endpoint
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "new@x.com", "password": "password123", "role": "viewer"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


def test_get_current_server_no_credentials(client):
    """Covers the None credentials path in get_current_server."""
    now = datetime.now(UTC)
    payload = {
        "server_id": None,
        "hostname": "web01",
        "distro": "ubuntu",
        "distro_version": "24.04",
        "agent_version": "0.1.0",
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "completed_at": now.isoformat(),
        "status": "completed",
        "guardian_results": [],
    }
    resp = client.post("/api/v1/agents/scans", json=payload)
    assert resp.status_code == 401


def test_get_current_user_missing_sub_in_token(client, monkeypatch):
    """Covers the missing 'sub' claim path in get_current_user."""
    import jwt as pyjwt

    from app.config import get_settings

    settings = get_settings()
    bad_token = pyjwt.encode(
        {"iat": datetime.now(UTC), "exp": datetime.now(UTC) + timedelta(minutes=10)},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert resp.status_code == 401


def test_get_current_user_deleted_user_token(client, admin_token):
    """Covers the 'user no longer exists' path in get_current_user."""
    from app.auth.jwt import create_access_token

    # Token for a user id that was never created
    orphan_token = create_access_token(subject="ghost-user-id-that-does-not-exist")
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {orphan_token}"})
    assert resp.status_code == 401


def test_report_with_computed_score_shows_score_section(client, auth_headers, db_session):
    """Covers report_service._render_markdown score-available branch.

    Scoring is now automatic (Phase 18) — no manual score insertion needed;
    the scan submission itself triggers computation.
    """
    reg = client.post("/api/v1/agents/register", json=_registration_body())
    api_key = reg.json()["api_key"]
    server_id = reg.json()["server"]["id"]
    now = datetime.now(UTC)
    client.post(
        "/api/v1/agents/scans",
        json={
            "server_id": server_id,
            "hostname": "web01",
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

    resp = client.get(f"/api/v1/servers/{server_id}/report?format=markdown", headers=auth_headers)
    assert resp.status_code == 200
    assert "100.0/100" in resp.json()["content"]
    assert "ssh" in resp.json()["content"]
