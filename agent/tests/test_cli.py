import json
from datetime import UTC

from typer.testing import CliRunner

from sentinelguard_agent.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "1.0.1"


def test_scan_command_prints_valid_json(monkeypatch):
    monkeypatch.delenv("SENTINELGUARD_API_KEY", raising=False)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    assert payload["status"] in ("completed", "partial", "failed")
    assert "hostname" in payload
    assert payload["distro"] in {
        "ubuntu",
        "debian",
        "fedora",
        "rocky",
        "centos",
        "unknown",
    }
    # guardian_results now has entries since Guardians are registered
    assert isinstance(payload["guardian_results"], list)


def test_scan_submit_without_api_key_fails_cleanly(monkeypatch):
    monkeypatch.delenv("SENTINELGUARD_API_KEY", raising=False)
    result = runner.invoke(app, ["scan", "--submit"])
    assert result.exit_code == 1
    assert "SENTINELGUARD_API_KEY" in result.output


def test_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "register" in result.stdout
    assert "version" in result.stdout


def test_scan_submit_success(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_API_KEY", "test-key")

    from sentinelguard_agent.transport.client import DashboardClient

    def fake_submit_scan(self, payload):
        return {"scan_id": "scan-1", "status": "accepted"}

    monkeypatch.setattr(DashboardClient, "submit_scan", fake_submit_scan)

    result = runner.invoke(app, ["scan", "--submit"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {"scan_id": "scan-1", "status": "accepted"}


def test_scan_submit_auth_error(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_API_KEY", "bad-key")

    from sentinelguard_agent.transport.client import DashboardAuthError, DashboardClient

    def fake_submit_scan(self, payload):
        raise DashboardAuthError("rejected")

    monkeypatch.setattr(DashboardClient, "submit_scan", fake_submit_scan)

    result = runner.invoke(app, ["scan", "--submit"])
    assert result.exit_code == 1
    assert "Authentication failed" in result.output


def test_scan_submit_client_error(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_API_KEY", "test-key")

    from sentinelguard_agent.transport.client import DashboardClient, DashboardClientError

    def fake_submit_scan(self, payload):
        raise DashboardClientError("unreachable")

    monkeypatch.setattr(DashboardClient, "submit_scan", fake_submit_scan)

    result = runner.invoke(app, ["scan", "--submit"])
    assert result.exit_code == 1
    assert "Failed to submit scan" in result.output


def test_register_success(monkeypatch):
    from datetime import datetime

    from sentinelguard_contracts import Distro, ServerInfo, ServerStatus

    from sentinelguard_agent.transport.client import DashboardClient

    def fake_register(self, registration):
        return ServerInfo(
            id="srv-1",
            hostname=registration.hostname,
            distro=Distro.UBUNTU,
            distro_version="24.04",
            agent_version="0.1.0",
            status=ServerStatus.ONLINE,
            created_at=datetime.now(UTC),
        )

    monkeypatch.setattr(DashboardClient, "register", fake_register)

    result = runner.invoke(app, ["register"])
    assert result.exit_code == 0
    assert "srv-1" in result.output
    assert "SENTINELGUARD_SERVER_ID" in result.output


def test_register_failure(monkeypatch):
    from sentinelguard_agent.transport.client import DashboardClient, DashboardClientError

    def fake_register(self, registration):
        raise DashboardClientError("dashboard unreachable")

    monkeypatch.setattr(DashboardClient, "register", fake_register)

    result = runner.invoke(app, ["register"])
    assert result.exit_code == 1
    assert "Registration failed" in result.output
