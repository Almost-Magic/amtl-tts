"""Wazuh integration models — SIEM alerts and correlation results."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class WazuhConnection(Base):
    """Configuration for connecting to a Wazuh SIEM instance."""

    __tablename__ = "wazuh_connections"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    api_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_user: Mapped[str] = mapped_column(String(100), nullable=False)
    api_password_encrypted: Mapped[str] = mapped_column(String(500), nullable=False)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<WazuhConnection org={self.org_id[:8]}>"


class WazuhAlert(Base):
    """A Wazuh alert pulled from the SIEM."""

    __tablename__ = "wazuh_alerts"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    wazuh_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_description: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    agent_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    agent_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="general")
    plain_english: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<WazuhAlert {self.wazuh_id}>"


class CorrelationResult(Base):
    """Cross-domain correlation between Wazuh and Digital Sentinel findings."""

    __tablename__ = "correlation_results"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    correlation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    wazuh_alert_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_pattern: Mapped[str | None] = mapped_column(String(100), nullable=True)
    plain_english: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<CorrelationResult {self.title[:40]}>"
