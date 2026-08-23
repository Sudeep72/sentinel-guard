"""Agent registration response schema."""

from __future__ import annotations

from pydantic import BaseModel
from sentinelguard_contracts import ServerInfo


class AgentRegistrationResponse(BaseModel):
    """Returned once, at registration time, so the agent can store its key.

    The plaintext ``api_key`` is never retrievable again after this
    response — only its hash is persisted.
    """

    server: ServerInfo
    api_key: str


class ScanSubmissionResponse(BaseModel):
    """Returned after a scan is successfully ingested."""

    scan_id: str
    status: str
