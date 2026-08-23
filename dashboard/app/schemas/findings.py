"""REST/MCP-facing finding representation.

Extends the shared ``Finding`` contract (from ``sentinelguard_contracts``)
with the persistence metadata that only exists once a finding has been
stored — its database id, which scan/server it belongs to, its
lifecycle status, and when it was recorded. The agent-emitted wire
format (no id yet, since the agent doesn't persist anything) stays
exactly as defined in the shared contract; this is strictly additive.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict
from sentinelguard_contracts import Finding, FindingStatus


class FindingRecord(Finding):
    """A Finding as stored and returned by the Dashboard."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    server_id: str
    status: FindingStatus
    created_at: datetime
