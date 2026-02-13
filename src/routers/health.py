"""Health check endpoints for production monitoring."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from src.schemas.health import HealthResponse, ServiceHealth

router = APIRouter(tags=["health"])


async def _check_service(name: str, check_fn) -> ServiceHealth:
    """Run a health check function and return a ServiceHealth result."""
    start = time.monotonic()
    try:
        await check_fn()
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service=name,
            status="healthy",
            latency_ms=round(latency, 2),
        )
    except Exception as exc:
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service=name,
            status="unhealthy",
            latency_ms=round(latency, 2),
            details=str(exc)[:200],
        )


async def _check_app() -> None:
    """Application self-check — always passes."""
    pass


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """Basic health check — is the application running?"""
    settings = request.app.state.settings
    app_health = await _check_service("app", _check_app)

    services = [app_health]
    overall = "healthy" if all(s.status == "healthy" for s in services) else "degraded"

    return HealthResponse(
        status=overall,
        version=settings.app_version,
        environment=settings.environment,
        services=services,
    )


@router.get("/health/ready", response_model=HealthResponse)
async def readiness_check(request: Request) -> HealthResponse:
    """Readiness check — are all dependencies available?

    In production this would check PostgreSQL, Redis, Neo4j, etc.
    For now we check the application itself.
    """
    settings = request.app.state.settings
    services = [await _check_service("app", _check_app)]

    overall = "healthy" if all(s.status == "healthy" for s in services) else "unhealthy"

    return HealthResponse(
        status=overall,
        version=settings.app_version,
        environment=settings.environment,
        services=services,
    )


@router.get("/health/live")
async def liveness_check() -> dict[str, str]:
    """Liveness probe — is the process alive?"""
    return {"status": "alive"}
