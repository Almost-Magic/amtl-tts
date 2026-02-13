"""Digital Sentinel — FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from src.config import Settings, get_settings
from src.middleware import configure_cors, configure_rate_limiting, lifespan
from src.routers import benchmarks, health, wazuh


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="Digital Sentinel",
        description="AI-powered cybersecurity assessment platform",
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Store settings on app state
    app.state.settings = settings

    # Middleware
    configure_cors(app, settings)
    configure_rate_limiting(app, settings)

    # Routers
    app.include_router(health.router)
    app.include_router(wazuh.router)
    app.include_router(benchmarks.router)

    return app


# Default app instance for uvicorn
app = create_app()
