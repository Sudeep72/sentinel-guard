import pytest
from pydantic import ValidationError

from sentinelguard_agent.config import AgentSettings


def test_defaults_when_no_env_vars(monkeypatch):
    for var in [
        "SENTINELGUARD_DASHBOARD_URL",
        "SENTINELGUARD_API_KEY",
        "SENTINELGUARD_SERVER_ID",
        "SENTINELGUARD_SCAN_INTERVAL_SECONDS",
        "SENTINELGUARD_LOG_LEVEL",
    ]:
        monkeypatch.delenv(var, raising=False)

    settings = AgentSettings(_env_file=None)
    assert settings.dashboard_url == "http://localhost:8000"
    assert settings.api_key is None
    assert settings.scan_interval_seconds == 3600
    assert settings.max_retries == 3
    assert settings.log_level == "INFO"


def test_env_var_overrides(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_DASHBOARD_URL", "https://dash.internal")
    monkeypatch.setenv("SENTINELGUARD_API_KEY", "secret-key")
    monkeypatch.setenv("SENTINELGUARD_SERVER_ID", "srv-42")
    monkeypatch.setenv("SENTINELGUARD_SCAN_INTERVAL_SECONDS", "600")
    monkeypatch.setenv("SENTINELGUARD_LOG_LEVEL", "DEBUG")

    settings = AgentSettings(_env_file=None)
    assert settings.dashboard_url == "https://dash.internal"
    assert settings.api_key == "secret-key"
    assert settings.server_id == "srv-42"
    assert settings.scan_interval_seconds == 600
    assert settings.log_level == "DEBUG"


def test_rejects_non_positive_scan_interval(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_SCAN_INTERVAL_SECONDS", "0")
    with pytest.raises(ValidationError):
        AgentSettings(_env_file=None)


def test_rejects_max_retries_out_of_range(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_MAX_RETRIES", "20")
    with pytest.raises(ValidationError):
        AgentSettings(_env_file=None)


def test_ignores_unrelated_env_vars(monkeypatch):
    monkeypatch.setenv("SOME_UNRELATED_VAR", "whatever")
    # Should not raise despite `extra="ignore"` not being about this var
    # specifically (unrelated vars simply aren't prefixed, so pydantic-settings
    # never considers them) — this just documents the expectation.
    settings = AgentSettings(_env_file=None)
    assert settings.dashboard_url == "http://localhost:8000"
