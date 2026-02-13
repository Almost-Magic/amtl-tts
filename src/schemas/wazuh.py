"""Schemas for Wazuh integration endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class WazuhConnectRequest(BaseModel):
    """Request to configure a Wazuh connection."""

    org_id: str
    api_url: str = Field(..., description="Wazuh API URL e.g. https://wazuh.example.com:55000")
    api_user: str
    api_password: str
    verify_ssl: bool = True


class WazuhConnectResponse(BaseModel):
    """Response after configuring Wazuh connection."""

    org_id: str
    api_url: str
    is_active: bool
    message: str


class WazuhAlertResponse(BaseModel):
    """A Wazuh alert translated to plain English."""

    id: str
    wazuh_id: str
    rule_id: str
    rule_description: str
    rule_level: int
    agent_name: str | None = None
    agent_ip: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    category: str
    plain_english: str | None = None
    timestamp: datetime


class CorrelationRequest(BaseModel):
    """Request to run cross-domain correlation."""

    time_range_hours: int = Field(default=24, ge=1, le=720)
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class CorrelationResponse(BaseModel):
    """A single cross-domain correlation finding."""

    id: str
    correlation_type: str
    severity: str
    confidence: float
    title: str
    description: str | None = None
    attack_pattern: str | None = None
    plain_english: str | None = None
    wazuh_alert_ids: list[str] = []
    vulnerability_ids: list[str] = []


class CorrelateResult(BaseModel):
    """Result of running cross-domain correlation."""

    org_id: str
    correlations_found: int
    high_severity_count: int
    correlations: list[CorrelationResponse]
    summary: str


class TimelineEvent(BaseModel):
    """A single event in the unified threat timeline."""

    timestamp: datetime
    source: str = Field(..., description="'wazuh' or 'digital_sentinel'")
    event_type: str
    severity: str
    title: str
    description: str | None = None
    plain_english: str | None = None
    related_ids: list[str] = []


class TimelineResponse(BaseModel):
    """Unified threat timeline combining both perspectives."""

    org_id: str
    time_range_hours: int
    total_events: int
    events: list[TimelineEvent]
    summary: str
