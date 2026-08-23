"""Auth request/response DTOs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class TokenResponse(BaseModel):
    """Response body for a successful login."""

    access_token: str
    token_type: str = "bearer"


class UserCreateRequest(BaseModel):
    """Request body for creating a new dashboard user (admin-only endpoint)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=8)
    role: str = Field(default="viewer", pattern="^(admin|viewer)$")


class UserResponse(BaseModel):
    """Public user representation (never includes the password hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: str
