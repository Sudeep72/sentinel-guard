"""Agent configuration, loaded from environment variables (and optionally
a local .env file for development).

All settings are prefixed ``SENTINELGUARD_`` — e.g. the dashboard URL is
configured via ``SENTINELGUARD_DASHBOARD_URL``. Nothing is hardcoded;
every value here has a sane local-dev default but is meant to be
overridden per deployment.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    """Runtime configuration for the SentinelGuard Agent.

    Attributes:
        dashboard_url: Base URL of the SentinelGuard Dashboard the agent
            reports to.
        api_key: Per-server API key issued at registration. Required
            for ``--submit`` scans; not required for local dry-run scans.
        server_id: Dashboard-issued server id, set after registration.
        scan_interval_seconds: Interval for daemon-mode scheduled scans
            (daemon mode itself is out of scope for the CLI framework in
            Phase 3; this setting exists for the systemd-timer / cron
            deployment pattern described in ARCHITECTURE.md).
        request_timeout_seconds: HTTP timeout for dashboard requests.
        max_retries: Max attempts for a dashboard request before giving up.
        log_level: Python logging level name.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINELGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dashboard_url: str = "http://localhost:8000"
    api_key: str | None = None
    server_id: str | None = None
    scan_interval_seconds: int = Field(default=3600, gt=0)
    request_timeout_seconds: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=3, ge=1, le=10)
    log_level: str = "INFO"
