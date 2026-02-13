"""Benchmark models — industry comparative analytics."""

from __future__ import annotations

from sqlalchemy import Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class BenchmarkRecord(Base):
    """Anonymised benchmark data point for an organisation."""

    __tablename__ = "benchmark_records"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    industry_sector: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(7), nullable=False)  # YYYY-MM
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    remediation_velocity: Mapped[float] = mapped_column(Float, default=0.0)
    culture_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    def __repr__(self) -> str:
        return f"<BenchmarkRecord org={self.org_id[:8]} period={self.period}>"


class IndustrySnapshot(Base):
    """Aggregated industry-level statistics for a period."""

    __tablename__ = "industry_snapshots"

    industry_sector: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(7), nullable=False)
    org_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_vulnerability_count: Mapped[float] = mapped_column(Float, default=0.0)
    avg_remediation_velocity: Mapped[float] = mapped_column(Float, default=0.0)
    avg_culture_score: Mapped[float] = mapped_column(Float, default=0.0)
    avg_compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    avg_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    median_vulnerability_count: Mapped[float] = mapped_column(Float, default=0.0)
    p25_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    p75_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<IndustrySnapshot {self.industry_sector} {self.period}>"
