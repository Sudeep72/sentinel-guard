"""Server registration and info models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinelguard_contracts.enums import Distro, ServerStatus


class ServerRegistration(BaseModel):
    """What an agent sends when registering itself with the dashboard.

    The dashboard issues an ``id`` and API key in response; the agent
    never generates its own server id.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str | None = None
    distro: Distro
    distro_version: str | None = None
    agent_version: str = Field(min_length=1)


class ServerInfo(BaseModel):
    """Full server record as returned by the dashboard API."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    hostname: str
    ip_address: str | None = None
    distro: Distro
    distro_version: str | None = None
    agent_version: str
    status: ServerStatus
    last_seen_at: datetime | None = None
    created_at: datetime
