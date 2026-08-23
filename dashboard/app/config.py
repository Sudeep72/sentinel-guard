"""Dashboard configuration, loaded from environment variables.

Mirrors the agent's convention: everything configurable lives here, no
hardcoded values scattered through the codebase.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the SentinelGuard Dashboard.

    Attributes:
        database_url: SQLAlchemy connection string.
        jwt_secret_key: Secret used to sign user JWTs. Must be overridden
            in any non-local deployment.
        jwt_algorithm: JWT signing algorithm.
        jwt_access_token_expire_minutes: User session token lifetime.
        environment: Deployment environment name, used for log verbosity
            and error detail exposure decisions.
        log_level: Python logging level name.
        cors_allow_origins: Origins allowed to call the API from a browser
            (the Next.js frontend, in later phases).
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINELGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./data/sentinelguard.db"

    jwt_secret_key: str = "changeme-generate-a-real-secret-at-least-32-bytes-long"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = Field(default=60, gt=0)

    environment: str = "development"
    log_level: str = "INFO"

    cors_allow_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])


def get_settings() -> Settings:
    """Return a fresh Settings instance.

    Not cached (e.g. via lru_cache) so tests can freely monkeypatch
    environment variables between cases without stale-settings bugs.
    Instantiation is cheap; this isn't a hot path.
    """
    return Settings()
