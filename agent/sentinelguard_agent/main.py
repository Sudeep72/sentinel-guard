"""SentinelGuard Agent CLI.

Commands:
    scan       Run all registered Guardians and print (or submit) the result.
    register   Register this host with the dashboard.
    version    Print the agent version.
"""

from __future__ import annotations

import json
import socket

import typer

from sentinelguard_agent import __version__
from sentinelguard_agent.aggregator import run_scan
from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY
from sentinelguard_agent.config import AgentSettings
from sentinelguard_agent.distro.detect import detect_distro
from sentinelguard_agent.logging_config import configure_logging
from sentinelguard_agent.transport.client import (
    DashboardAuthError,
    DashboardClient,
    DashboardClientError,
)

app = typer.Typer(help="SentinelGuard Linux Agent")


@app.command()
def scan(
    submit: bool = typer.Option(
        False, "--submit", help="Submit the scan to the dashboard instead of printing it."
    ),
) -> None:
    """Run all registered Guardians and print the resulting ScanPayload as JSON.

    As of Phase 3 (framework only, no Guardians implemented yet), this
    runs zero Guardians and produces an empty-but-valid COMPLETED scan —
    proving the collection -> aggregation -> (optional) submission
    pipeline end-to-end ahead of Guardians landing in Phases 8-16.
    """
    settings = AgentSettings()
    configure_logging(settings.log_level)

    distro, distro_version = detect_distro()
    guardians = [guardian_cls() for guardian_cls in GUARDIAN_REGISTRY]

    payload = run_scan(
        guardians=guardians,
        hostname=socket.gethostname(),
        distro=distro,
        distro_version=distro_version,
        agent_version=__version__,
        server_id=settings.server_id,
    )

    if not submit:
        typer.echo(payload.model_dump_json(indent=2))
        return

    if not settings.api_key:
        typer.echo("Error: --submit requires SENTINELGUARD_API_KEY to be set.", err=True)
        raise typer.Exit(code=1)

    with DashboardClient(
        base_url=settings.dashboard_url,
        api_key=settings.api_key,
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    ) as client:
        try:
            result = client.submit_scan(payload)
        except DashboardAuthError as exc:
            typer.echo(f"Authentication failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except DashboardClientError as exc:
            typer.echo(f"Failed to submit scan: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    typer.echo(json.dumps(result, indent=2))


@app.command()
def register() -> None:
    """Register this host with the dashboard and print the assigned ServerInfo.

    Note: the dashboard's registration endpoint doesn't exist until
    Phase 4, so this command will fail with a connection error until
    then — it's included now so the agent's side of the registration
    flow is complete and testable in isolation (see tests/test_cli.py,
    which exercises this against a mock transport).
    """
    from sentinelguard_contracts import ServerRegistration

    settings = AgentSettings()
    configure_logging(settings.log_level)

    distro, distro_version = detect_distro()
    registration = ServerRegistration(
        hostname=socket.gethostname(),
        distro=distro,
        distro_version=distro_version,
        agent_version=__version__,
    )

    with DashboardClient(
        base_url=settings.dashboard_url,
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    ) as client:
        try:
            server_info = client.register(registration)
        except DashboardClientError as exc:
            typer.echo(f"Registration failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    typer.echo(server_info.model_dump_json(indent=2))
    typer.echo(
        "\nSet SENTINELGUARD_SERVER_ID and SENTINELGUARD_API_KEY using the "
        "values returned by the dashboard to enable `scan --submit`.",
        err=True,
    )


@app.command()
def version() -> None:
    """Print the agent version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
