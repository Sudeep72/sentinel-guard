"""Authentication endpoints: user registration and login."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_admin_or_bootstrap
from app.auth.jwt import create_access_token
from app.core.exceptions import AuthenticationError, ConflictError
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import TokenResponse, UserCreateRequest, UserResponse
from app.services.auth_service import authenticate_user, register_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_or_bootstrap)],
)
def register(request: UserCreateRequest, db: Session = Depends(get_db)) -> User:
    """Create a new user.

    The first user ever created on a fresh dashboard is automatically
    granted admin (bootstrap) — see ``require_admin_or_bootstrap``.
    Every subsequent call requires an authenticated admin.
    """
    try:
        return register_user(db, email=request.email, password=request.password, role=request.role)
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/token", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> TokenResponse:
    """Authenticate with email (as ``username``) + password, returning a JWT."""
    try:
        user = authenticate_user(db, email=form_data.username, password=form_data.password)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    token = create_access_token(subject=user.id, extra_claims={"role": user.role})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
def read_current_user(user: User = Depends(get_current_user)) -> User:
    """Return the currently authenticated user."""
    return user
