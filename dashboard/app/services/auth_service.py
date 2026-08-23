"""User authentication and registration.

Bootstrap rule: the very first user created on a fresh dashboard is
always granted the ``admin`` role regardless of what was requested,
since there's no existing admin yet to have approved a different role.
Every subsequent registration must be performed by an authenticated
admin (enforced by the route dependency, not here) and gets whatever
role was requested.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.auth.security import hash_password, verify_password
from app.core.exceptions import AuthenticationError, ConflictError
from app.models.user import User


def is_bootstrap_needed(db: Session) -> bool:
    """True if no users exist yet (first-run state)."""
    return db.query(User).count() == 0


def register_user(db: Session, email: str, password: str, role: str) -> User:
    """Create a new user.

    Raises:
        ConflictError: If a user with this email already exists.
    """
    existing = db.query(User).filter(User.email == email).one_or_none()
    if existing is not None:
        raise ConflictError(f"A user with email {email!r} already exists")

    effective_role = "admin" if is_bootstrap_needed(db) else role
    user = User(email=email, hashed_password=hash_password(password), role=effective_role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User:
    """Verify credentials and return the matching user.

    Raises:
        AuthenticationError: If the email is unknown or the password is wrong.
    """
    user = db.query(User).filter(User.email == email).one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        raise AuthenticationError("Invalid email or password")
    return user
