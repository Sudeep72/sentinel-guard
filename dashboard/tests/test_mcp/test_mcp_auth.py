"""Coverage for MCP server auth edge cases."""

import pytest

from app.mcp.server import authenticate_session


def test_authenticate_session_prints_to_stderr_on_missing_token(capsys):
    with pytest.raises(SystemExit):
        authenticate_session(None)
    captured = capsys.readouterr()
    assert "SENTINELGUARD_MCP_TOKEN" in captured.err


def test_authenticate_session_prints_to_stderr_on_invalid_token(capsys):
    with pytest.raises(SystemExit):
        authenticate_session("invalid-token-value")
    captured = capsys.readouterr()
    assert "invalid or expired" in captured.err
