"""HTTPS client for agent -> dashboard communication.

The agent is outbound-only: it never opens inbound ports. Every call
here is a client-initiated HTTPS request to the dashboard's ingest API.

Retry policy: transient network errors and 5xx responses are retried
with exponential backoff up to ``max_retries`` attempts. 4xx responses
(other than throttling, not yet implemented dashboard-side) are treated
as non-retryable client errors — retrying a malformed request won't fix
it.
"""

from __future__ import annotations

import time
from types import TracebackType
from typing import Any

import httpx
from sentinelguard_contracts import ScanPayload, ServerInfo, ServerRegistration


class DashboardClientError(Exception):
    """Base exception for dashboard communication failures."""


class DashboardAuthError(DashboardClientError):
    """Raised when the dashboard rejects the API key (401)."""


class DashboardClient:
    """Authenticated client for the SentinelGuard Dashboard's agent-facing API."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Create a dashboard client.

        Args:
            base_url: Dashboard base URL, e.g. ``https://dashboard.example.com``.
            api_key: Per-server API key. Omit only for registration, which
                is how a server obtains its key in the first place.
            timeout: Per-request timeout in seconds.
            max_retries: Max attempts before raising ``DashboardClientError``.
            transport: Optional ``httpx.BaseTransport`` override, used in
                tests to inject a mock transport instead of hitting the network.
        """
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self._max_retries = max_retries
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    def register(self, registration: ServerRegistration) -> ServerInfo:
        """Register this host with the dashboard, returning the assigned ServerInfo."""
        response = self._request(
            "POST",
            "/api/v1/agents/register",
            json_body=registration.model_dump(mode="json"),
        )
        return ServerInfo.model_validate(response.json())

    def submit_scan(self, payload: ScanPayload) -> dict[str, object]:
        """Submit a completed scan payload to the dashboard."""
        response = self._request(
            "POST",
            "/api/v1/agents/scans",
            json_body=payload.model_dump(mode="json"),
        )
        result: dict[str, object] = response.json()
        return result

    def _request(
        self, method: str, path: str, json_body: dict[str, Any] | None = None
    ) -> httpx.Response:
        last_exception: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._client.request(method, path, json=json_body)
            except httpx.TransportError as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_backoff_seconds(attempt))
                    continue
                raise DashboardClientError(
                    f"Failed to reach dashboard at {path!r} after {attempt} attempts"
                ) from exc

            if response.status_code == 401:
                raise DashboardAuthError(f"Dashboard rejected credentials for {path!r}")

            if response.status_code >= 500 and attempt < self._max_retries:
                time.sleep(_backoff_seconds(attempt))
                continue

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise DashboardClientError(
                    f"Dashboard returned {response.status_code} for {path!r}"
                ) from exc

            return response

        # Unreachable in practice (loop always returns or raises), but keeps
        # mypy --strict happy about the function's return type.
        raise DashboardClientError(f"Request to {path!r} failed") from last_exception

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> DashboardClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def _backoff_seconds(attempt: int) -> float:
    """Exponential backoff: 0.1s, 0.2s, 0.4s, ..."""
    return float(0.1 * (2 ** (attempt - 1)))
