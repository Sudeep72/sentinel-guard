# transport/

HTTPS client responsible for authenticated communication with the
SentinelGuard Dashboard's ingest API. Contains:

- `client.py` — outbound HTTPS client with retry/backoff (Phase 3)
- `schemas.py` — pydantic models for the wire contract shared with the
  dashboard (`ScanPayload`, `GuardianResult`, etc.) (Phase 2)

The agent never opens inbound ports; all communication is outbound-only.
