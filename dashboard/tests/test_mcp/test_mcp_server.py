import pytest

from app.auth.jwt import create_access_token
from app.mcp.server import authenticate_session, mcp_app


def test_authenticate_session_missing_token_exits():
    with pytest.raises(SystemExit):
        authenticate_session(None)


def test_authenticate_session_empty_token_exits():
    with pytest.raises(SystemExit):
        authenticate_session("")


def test_authenticate_session_invalid_token_exits():
    with pytest.raises(SystemExit):
        authenticate_session("not-a-real-token")


def test_authenticate_session_valid_token_succeeds():
    token = create_access_token(subject="user-123", extra_claims={"role": "admin"})
    # Should not raise.
    authenticate_session(token)


@pytest.mark.asyncio
async def test_all_eight_required_tools_are_registered():
    expected = {
        "health",
        "scan_server",
        "get_security_score",
        "list_findings",
        "explain_finding",
        "compare_to_baseline",
        "generate_report",
        "list_servers",
    }
    tools = await mcp_app.list_tools()
    registered = {tool.name for tool in tools}
    assert registered == expected
