"""Scan summary schema for REST list/detail endpoints.

The persisted Scan row doesn't need the full agent-submitted
``ScanPayload`` shape (hostname/distro are on the Server, not
re-duplicated per scan in responses) — this is a deliberately lighter
REST-facing view.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanSummary(BaseModel):
    """Summary of one scan run."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    server_id: str
    started_at: datetime
    completed_at: datetime
    status: str
    agent_version: str
