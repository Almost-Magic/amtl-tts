"""Application middleware — rate limiting, CORS, logging, shutdown."""

from __future__ import annotations

import signal
import time
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.config import Settings

logger = structlog.get_logger()


def get_limiter(settings: Settings) -> Limiter:
    """Create a rate limiter instance."""
    return Limiter(
        key_func=get_remote_address,
        default_limits=[settings.rate_limit_default],
    )


def configure_cors(app: FastAPI, settings: Settings) -> None:
    """Add CORS middleware to the application."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
    )


def configure_rate_limiting(app: FastAPI, settings: Settings) -> None:
    """Add rate limiting to the application."""
    limiter = get_limiter(settings)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


async def logging_middleware(request: Request, call_next) -> Response:
    """Structured logging middleware — logs every request."""
    start_time = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - start_time) * 1000, 2)

    logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        client_ip=request.client.host if request.client else "unknown",
    )

    return response


def configure_structured_logging(settings: Settings) -> None:
    """Configure structlog for JSON or console output."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


_shutdown_requested = False


def is_shutdown_requested() -> bool:
    """Check if graceful shutdown has been requested."""
    return _shutdown_requested


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown handlers."""
    global _shutdown_requested

    settings = app.state.settings
    configure_structured_logging(settings)

    logger.info("application_starting", version=settings.app_version, environment=settings.environment)

    # Register signal handlers for graceful shutdown
    def _handle_signal(signum, frame):
        global _shutdown_requested
        _shutdown_requested = True
        logger.info("shutdown_signal_received", signal=signum)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    yield

    logger.info("application_shutting_down")
    _shutdown_requested = True
