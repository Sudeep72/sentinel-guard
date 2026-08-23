"""FastAPI dependencies enforcing authentication.

Two separate schemes, matching the two separate identities in the
system:

- ``get_current_user``: OAuth2 bearer JWT, for human dashboard users
  hitting the REST API (and, transitively, anything the MCP layer does
  on a user's behalf — see ``app/mcp/server.py``).
- ``get_current_server``: HTTP bearer API key, for agents submitting
  scans. Deliberately a *different* dependency so a leaked user JWT
  can't be used to impersonate an agent and vice versa.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.auth.jwt import InvalidTokenError, decode_access_token
from app.auth.security import hash_api_key
from app.db.session import get_db
from app.models.server import Server
from app.models.user import User

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
_agent_bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    token: str | None = Depends(_oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the authenticated user from a JWT bearer token.

    Raises:
        HTTPException: 401 if the token is missing, invalid, expired, or
            no longer matches a real user.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token is None:
        raise unauthorized

    try:
        claims = decode_access_token(token)
    except InvalidTokenError as exc:
        raise unauthorized from exc

    user_id = claims.get("sub")
    if not user_id:
        raise unauthorized

    user = db.get(User, user_id)
    if user is None:
        raise unauthorized

    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Dependency for endpoints restricted to admin-role users."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an admin account.",
        )
    return user


def get_current_server(
    credentials: HTTPAuthorizationCredentials | None = Depends(_agent_bearer_scheme),
    db: Session = Depends(get_db),
) -> Server:
    """Resolve the authenticated server from its API key.

    Raises:
        HTTPException: 401 if no key was supplied or it doesn't match
            any registered server.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing agent API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    key_hash = hash_api_key(credentials.credentials)
    server = db.query(Server).filter(Server.api_key_hash == key_hash).one_or_none()
    if server is None:
        raise unauthorized

    return server


def require_admin_or_bootstrap(
    token: str | None = Depends(_oauth2_scheme),
    db: Session = Depends(get_db),
) -> None:
    """Allow the request through if no users exist yet (first-run bootstrap),
    otherwise require a valid admin JWT.

    This is what lets a fresh dashboard create its first (admin) account
    without a chicken-and-egg problem, while every subsequent user
    registration requires an existing admin to approve it.
    """
    from app.services.auth_service import is_bootstrap_needed

    if is_bootstrap_needed(db):
        return

    user = get_current_user(token=token, db=db)
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an admin account.",
        )
