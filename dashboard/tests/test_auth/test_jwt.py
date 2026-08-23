from datetime import UTC

import pytest

from app.auth.jwt import InvalidTokenError, create_access_token, decode_access_token


def test_create_and_decode_round_trip():
    token = create_access_token(subject="user-123")
    claims = decode_access_token(token)
    assert claims["sub"] == "user-123"


def test_extra_claims_included():
    token = create_access_token(subject="user-123", extra_claims={"role": "admin"})
    claims = decode_access_token(token)
    assert claims["role"] == "admin"


def test_decode_garbage_token_raises():
    with pytest.raises(InvalidTokenError):
        decode_access_token("not-a-real-jwt")


def test_decode_tampered_token_raises():
    token = create_access_token(subject="user-123")
    tampered = token[:-4] + "abcd"
    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered)


def test_decode_token_signed_with_different_secret_raises(monkeypatch):
    import app.config

    original_get_settings = app.config.get_settings

    token = create_access_token(subject="user-123")

    def different_secret_settings():
        settings = original_get_settings()
        settings.jwt_secret_key = "a-completely-different-secret"
        return settings

    monkeypatch.setattr("app.auth.jwt.get_settings", different_secret_settings)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_expired_token_raises():
    from datetime import datetime, timedelta

    import jwt as pyjwt

    from app.config import get_settings

    settings = get_settings()
    now = datetime.now(UTC)
    expired_payload = {
        "sub": "user-123",
        "iat": now - timedelta(minutes=10),
        "exp": now - timedelta(minutes=5),
    }
    expired_token = pyjwt.encode(
        expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )

    with pytest.raises(InvalidTokenError):
        decode_access_token(expired_token)
