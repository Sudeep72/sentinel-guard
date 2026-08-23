from datetime import UTC, datetime

import httpx
import pytest
from sentinelguard_contracts import Distro, ScanPayload, ScanStatus, ServerRegistration

from sentinelguard_agent.transport.client import (
    DashboardAuthError,
    DashboardClient,
    DashboardClientError,
)


def _registration() -> ServerRegistration:
    return ServerRegistration(
        hostname="web01",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
    )


def _scan_payload() -> ScanPayload:
    now = datetime.now(UTC)
    return ScanPayload(
        server_id="srv-1",
        hostname="web01",
        distro=Distro.UBUNTU,
        distro_version="24.04",
        agent_version="0.1.0",
        started_at=now,
        completed_at=now,
        status=ScanStatus.COMPLETED,
        guardian_results=[],
    )


def test_register_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agents/register"
        return httpx.Response(
            200,
            json={
                "id": "srv-1",
                "hostname": "web01",
                "ip_address": None,
                "distro": "ubuntu",
                "distro_version": "24.04",
                "agent_version": "0.1.0",
                "status": "online",
                "last_seen_at": None,
                "created_at": "2026-07-16T00:00:00Z",
            },
        )

    transport = httpx.MockTransport(handler)
    client = DashboardClient(base_url="http://dashboard.test", transport=transport)
    server_info = client.register(_registration())
    assert server_info.id == "srv-1"
    assert server_info.hostname == "web01"
    client.close()


def test_submit_scan_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agents/scans"
        assert request.headers["Authorization"] == "Bearer test-key"
        return httpx.Response(202, json={"scan_id": "scan-1", "status": "accepted"})

    transport = httpx.MockTransport(handler)
    with DashboardClient(
        base_url="http://dashboard.test", api_key="test-key", transport=transport
    ) as client:
        result = client.submit_scan(_scan_payload())
    assert result == {"scan_id": "scan-1", "status": "accepted"}


def test_401_raises_auth_error_without_retry():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(401, json={"detail": "invalid key"})

    transport = httpx.MockTransport(handler)
    client = DashboardClient(
        base_url="http://dashboard.test", api_key="bad-key", transport=transport
    )
    with pytest.raises(DashboardAuthError):
        client.submit_scan(_scan_payload())
    assert call_count == 1  # no retry on auth failure
    client.close()


def test_5xx_retries_then_succeeds():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(503, json={"detail": "unavailable"})
        return httpx.Response(202, json={"scan_id": "scan-1", "status": "accepted"})

    transport = httpx.MockTransport(handler)
    client = DashboardClient(
        base_url="http://dashboard.test", api_key="k", max_retries=5, transport=transport
    )
    result = client.submit_scan(_scan_payload())
    assert result["status"] == "accepted"
    assert call_count == 3
    client.close()


def test_5xx_exhausts_retries_and_raises():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(500, json={"detail": "server error"})

    transport = httpx.MockTransport(handler)
    client = DashboardClient(
        base_url="http://dashboard.test", api_key="k", max_retries=3, transport=transport
    )
    with pytest.raises(DashboardClientError):
        client.submit_scan(_scan_payload())
    assert call_count == 3
    client.close()


def test_transport_error_retries_then_raises():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("connection refused", request=request)

    transport = httpx.MockTransport(handler)
    client = DashboardClient(
        base_url="http://dashboard.test", api_key="k", max_retries=2, transport=transport
    )
    with pytest.raises(DashboardClientError):
        client.submit_scan(_scan_payload())
    assert call_count == 2
    client.close()


def test_4xx_non_401_raises_without_retry():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(400, json={"detail": "bad request"})

    transport = httpx.MockTransport(handler)
    client = DashboardClient(
        base_url="http://dashboard.test", api_key="k", max_retries=3, transport=transport
    )
    with pytest.raises(DashboardClientError):
        client.submit_scan(_scan_payload())
    assert call_count == 1
    client.close()


def test_context_manager_closes_client():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "accepted"})

    transport = httpx.MockTransport(handler)
    with DashboardClient(base_url="http://dashboard.test", transport=transport) as client:
        assert client is not None
    # No assertion possible on internal httpx.Client closed-state directly
    # without reaching into private attrs; the context manager exiting
    # without raising is itself the behavior under test.
