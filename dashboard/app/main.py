"""FastAPI application factory.

OpenAPI docs are generated automatically by FastAPI from the route
type hints and pydantic models — nothing hand-written — available at
``/docs`` (Swagger UI) and ``/redoc`` once the app is running.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.config import get_settings
from app.core.logging import configure_logging
from app.db.base import Base
from app.db.session import engine


def _register_analyzers() -> None:
    """Register all nine dashboard-side Guardian analyzers (v1 complete)."""
    from app.modules.cron.analyzer import CronAnalyzer
    from app.modules.docker.analyzer import DockerAnalyzer
    from app.modules.firewall.analyzer import FirewallAnalyzer
    from app.modules.kernel.analyzer import KernelAnalyzer
    from app.modules.ownership.analyzer import OwnershipAnalyzer
    from app.modules.permission.analyzer import PermissionAnalyzer
    from app.modules.registry import register_analyzer
    from app.modules.secret.analyzer import SecretAnalyzer
    from app.modules.ssh.analyzer import SSHAnalyzer
    from app.modules.sudo.analyzer import SudoAnalyzer

    register_analyzer(PermissionAnalyzer())
    register_analyzer(OwnershipAnalyzer())
    register_analyzer(SSHAnalyzer())
    register_analyzer(SudoAnalyzer())
    register_analyzer(CronAnalyzer())
    register_analyzer(SecretAnalyzer())
    register_analyzer(DockerAnalyzer())
    register_analyzer(FirewallAnalyzer())
    register_analyzer(KernelAnalyzer())


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()
    configure_logging(settings.log_level)
    _register_analyzers()

    app = FastAPI(
        title="SentinelGuard Dashboard",
        description=(
            "AI-native Linux hardening platform — REST API for the SentinelGuard "
            "Dashboard. See also the MCP server (app/mcp/server.py) for AI-client access "
            "backed by the exact same service layer as this API."
        ),
        version="1.0.1",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)

    return app


app = create_app()


def run() -> None:
    """Entrypoint for the ``sentinelguard-dashboard`` console script."""
    import uvicorn

    # Dev convenience only: creates tables directly rather than requiring
    # `alembic upgrade head` first, so `sentinelguard-dashboard` works out
    # of the box on a fresh clone. Real deployments should run Alembic
    # migrations explicitly instead of relying on this.
    Base.metadata.create_all(bind=engine)

    # Sync YAML baselines into the database (Phase 17) — safe to run on
    # every startup, upserts rather than duplicates. Not run inside
    # create_app() itself since tests call create_app() repeatedly
    # against an isolated in-memory database via dependency overrides,
    # and syncing here would hit the real production DB instead.
    from app.db.session import SessionLocal
    from app.services.baseline_engine_service import sync_baselines_to_db

    db = SessionLocal()
    try:
        sync_baselines_to_db(db)
    finally:
        db.close()

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
