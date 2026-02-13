"""Schemas for health check endpoints."""

from __future__ import annotations

from pydantic import BaseModel


class ServiceHealth(BaseModel):
    """Health status of a single service."""

    service: str
    status: str
    latency_ms: float | None = None
    details: str | None = None


class HealthResponse(BaseModel):
    """Overall application health."""

    status: str
    version: str
    environment: str
    services: list[ServiceHealth]
