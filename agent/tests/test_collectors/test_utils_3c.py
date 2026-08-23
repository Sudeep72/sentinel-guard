"""Tests for 3C shared utilities (sysctl, JSON runner, kernel version)."""

from __future__ import annotations

from unittest.mock import patch

from sentinelguard_agent.collectors.utils import (
    get_kernel_version,
    parse_kernel_version,
    read_sysctl,
    read_sysctl_all,
    run_command_json,
)

# ── parse_kernel_version ─────────────────────────────────────────────────────


def test_parse_kernel_version_standard():
    assert parse_kernel_version("5.15.0-91-generic") == (5, 15, 0)


def test_parse_kernel_version_simple():
    assert parse_kernel_version("6.1.0") == (6, 1, 0)


def test_parse_kernel_version_rhel():
    assert parse_kernel_version("4.18.0-477.el8.x86_64") == (4, 18, 0)


def test_parse_kernel_version_old():
    assert parse_kernel_version("3.10.0-1160.el7") == (3, 10, 0)


def test_parse_kernel_version_invalid():
    assert parse_kernel_version("not-a-version") == (0, 0, 0)


def test_parse_kernel_version_empty():
    assert parse_kernel_version("") == (0, 0, 0)


# ── get_kernel_version ───────────────────────────────────────────────────────


def test_get_kernel_version_uses_uname():
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value="5.15.0-91-generic\n",
    ):
        result = get_kernel_version()
    assert result == "5.15.0-91-generic"


def test_get_kernel_version_falls_back_to_platform(monkeypatch):
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value=None,
    ):
        monkeypatch.setattr(
            "sentinelguard_agent.collectors.utils._platform.release",
            lambda: "5.10.0-test",
        )
        result = get_kernel_version()
    assert result == "5.10.0-test"


# ── read_sysctl ──────────────────────────────────────────────────────────────


def test_read_sysctl_returns_value():
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value="2\n",
    ):
        result = read_sysctl("kernel.randomize_va_space")
    assert result == "2"


def test_read_sysctl_returns_none_when_unavailable():
    with patch("sentinelguard_agent.collectors.utils.run_command", return_value=None):
        result = read_sysctl("kernel.randomize_va_space")
    assert result is None


# ── read_sysctl_all ──────────────────────────────────────────────────────────


def test_read_sysctl_all_parses_output():
    fake_output = "kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n"
    with patch("sentinelguard_agent.collectors.utils.run_command", return_value=fake_output):
        result = read_sysctl_all()
    assert result["kernel.randomize_va_space"] == "2"
    assert result["net.ipv4.ip_forward"] == "0"


def test_read_sysctl_all_returns_empty_when_unavailable():
    with patch("sentinelguard_agent.collectors.utils.run_command", return_value=None):
        result = read_sysctl_all()
    assert result == {}


def test_read_sysctl_all_skips_lines_without_equals():
    fake_output = "# comment\nkey = value\nbadline\n"
    with patch("sentinelguard_agent.collectors.utils.run_command", return_value=fake_output):
        result = read_sysctl_all()
    assert "key" in result
    assert "badline" not in result


# ── run_command_json ─────────────────────────────────────────────────────────


def test_run_command_json_parses_list():
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value='[{"id": "abc123", "Name": "/web"}]',
    ):
        result = run_command_json(["docker", "inspect", "web"])
    assert isinstance(result, list)
    assert result[0]["id"] == "abc123"


def test_run_command_json_parses_dict():
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value='{"status": "ok"}',
    ):
        result = run_command_json(["docker", "version"])
    assert isinstance(result, dict)
    assert result["status"] == "ok"


def test_run_command_json_returns_none_on_invalid_json():
    with patch(
        "sentinelguard_agent.collectors.utils.run_command",
        return_value="not json",
    ):
        result = run_command_json(["docker", "version"])
    assert result is None


def test_run_command_json_returns_none_when_command_fails():
    with patch("sentinelguard_agent.collectors.utils.run_command", return_value=None):
        result = run_command_json(["docker", "version"])
    assert result is None
