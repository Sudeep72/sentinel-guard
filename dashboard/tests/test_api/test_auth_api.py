def test_bootstrap_first_user_becomes_admin_no_auth_needed(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "viewer"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["role"] == "admin"  # bootstrap forces admin regardless of requested role
    assert body["email"] == "admin@example.com"
    assert "password" not in body
    assert "hashed_password" not in body


def test_second_registration_requires_admin_auth(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "second@example.com", "password": "pass12345", "role": "viewer"},
    )
    assert resp.status_code == 401


def test_second_registration_succeeds_with_admin_token(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    token_resp = client.post(
        "/api/v1/auth/token", data={"username": "admin@example.com", "password": "adminpass123"}
    )
    token = token_resp.json()["access_token"]

    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "second@example.com", "password": "pass12345", "role": "viewer"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"


def test_login_success_returns_token(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    resp = client.post(
        "/api/v1/auth/token", data={"username": "admin@example.com", "password": "adminpass123"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


def test_login_wrong_password_fails(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    resp = client.post(
        "/api/v1/auth/token", data={"username": "admin@example.com", "password": "wrongpass"}
    )
    assert resp.status_code == 401


def test_login_unknown_user_fails(client):
    resp = client.post(
        "/api/v1/auth/token", data={"username": "nobody@example.com", "password": "whatever"}
    )
    assert resp.status_code == 401


def test_me_endpoint_returns_current_user(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "adminpass123", "role": "admin"},
    )
    token = client.post(
        "/api/v1/auth/token", data={"username": "admin@example.com", "password": "adminpass123"}
    ).json()["access_token"]

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "admin@example.com"


def test_me_endpoint_without_token_fails(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_endpoint_with_garbage_token_fails(client):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage-token"})
    assert resp.status_code == 401


def test_register_password_too_short_rejected(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "short", "role": "admin"},
    )
    assert resp.status_code == 422


def test_register_invalid_email_rejected(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "validpass123", "role": "admin"},
    )
    assert resp.status_code == 422


def test_register_invalid_role_rejected(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "validpass123", "role": "superuser"},
    )
    assert resp.status_code == 422
