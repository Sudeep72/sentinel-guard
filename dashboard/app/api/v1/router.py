"""Aggregates all v1 REST routers under a single ``/api/v1`` prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import agents, auth, findings, health, reports, scores, servers

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(agents.router)
api_router.include_router(servers.router)
api_router.include_router(findings.router)
api_router.include_router(scores.router)
api_router.include_router(reports.router)
