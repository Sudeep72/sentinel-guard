import pytest

from app.core.exceptions import AuthenticationError, ConflictError
from app.services.auth_service import authenticate_user, is_bootstrap_needed, register_user


def test_is_bootstrap_needed_true_when_no_users(db_session):
    assert is_bootstrap_needed(db_session) is True


def test_is_bootstrap_needed_false_after_first_user(db_session):
    register_user(db_session, email="a@example.com", password="password123", role="viewer")
    assert is_bootstrap_needed(db_session) is False


def test_first_user_always_becomes_admin_regardless_of_requested_role(db_session):
    user = register_user(
        db_session, email="first@example.com", password="password123", role="viewer"
    )
    assert user.role == "admin"


def test_second_user_gets_requested_role(db_session):
    register_user(db_session, email="first@example.com", password="password123", role="viewer")
    second = register_user(
        db_session, email="second@example.com", password="password123", role="viewer"
    )
    assert second.role == "viewer"


def test_register_duplicate_email_raises_conflict(db_session):
    register_user(db_session, email="dupe@example.com", password="password123", role="admin")
    with pytest.raises(ConflictError):
        register_user(db_session, email="dupe@example.com", password="differentpass", role="viewer")


def test_authenticate_user_success(db_session):
    register_user(db_session, email="user@example.com", password="correctpass123", role="admin")
    user = authenticate_user(db_session, email="user@example.com", password="correctpass123")
    assert user.email == "user@example.com"


def test_authenticate_user_wrong_password_raises(db_session):
    register_user(db_session, email="user@example.com", password="correctpass123", role="admin")
    with pytest.raises(AuthenticationError):
        authenticate_user(db_session, email="user@example.com", password="wrongpass")


def test_authenticate_user_unknown_email_raises(db_session):
    with pytest.raises(AuthenticationError):
        authenticate_user(db_session, email="nobody@example.com", password="whatever")
