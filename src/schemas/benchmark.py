"""Schemas for Industry Benchmark Engine endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MetricPercentile(BaseModel):
    """A single metric with its value and percentile ranking."""

    metric: str
    value: float
    percentile: float = Field(..., ge=0.0, le=100.0)
    industry_average: float
    industry_median: float
    interpretation: str


class BenchmarkPosition(BaseModel):
    """An organisation's benchmark position within its industry."""

    org_id: str
    industry_sector: str
    period: str
    overall_percentile: float
    metrics: list[MetricPercentile]
    peer_count: int
    summary: str


class IndustryStat(BaseModel):
    """Aggregated statistics for an industry sector."""

    industry_sector: str
    period: str
    org_count: int
    avg_vulnerability_count: float
    avg_remediation_velocity: float
    avg_culture_score: float
    avg_compliance_score: float
    avg_risk_score: float
    median_vulnerability_count: float
    p25_risk_score: float
    p75_risk_score: float


class IndustryStatsResponse(BaseModel):
    """Industry statistics response."""

    industry_sector: str
    current_period: str
    stats: IndustryStat
    summary: str


class TrendPoint(BaseModel):
    """A single data point in a trend series."""

    period: str
    value: float
    change_pct: float | None = None


class TrendSeries(BaseModel):
    """A trend line for a specific metric."""

    metric: str
    data_points: list[TrendPoint]
    direction: str = Field(..., description="'improving', 'worsening', or 'stable'")
    interpretation: str


class TrendResponse(BaseModel):
    """Industry trend data over time."""

    industry_sector: str
    periods_covered: int
    trends: list[TrendSeries]
    summary: str


class CompareRequest(BaseModel):
    """Request for comparative analysis."""

    compare_sectors: list[str] = Field(
        default_factory=list,
        description="Additional sectors to compare against. Empty = same sector only.",
    )
    periods: int = Field(default=6, ge=1, le=24, description="Number of months to analyse")


class CompareResponse(BaseModel):
    """Comparative analysis result."""

    org_id: str
    industry_sector: str
    period: str
    rankings: list[MetricPercentile]
    strengths: list[str]
    weaknesses: list[str]
    recommendations: list[str]
    peer_count: int
    summary: str
