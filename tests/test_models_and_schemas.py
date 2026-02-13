"""Beast tests for models and schemas — structural validation.

Covers: model field validation, schema serialisation, Pydantic model
behaviour, and data integrity checks across all models.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.schemas.wazuh import (
    CorrelateResult,
    CorrelationRequest,
    CorrelationResponse,
    TimelineEvent,
    TimelineResponse,
    WazuhAlertResponse,
    WazuhConnectRequest,
    WazuhConnectResponse,
)
from src.schemas.benchmark import (
    BenchmarkPosition,
    CompareRequest,
    CompareResponse,
    IndustryStat,
    IndustryStatsResponse,
    MetricPercentile,
    TrendPoint,
    TrendResponse,
    TrendSeries,
)
from src.schemas.health import HealthResponse, ServiceHealth
from src.models.base import Base, utcnow
from src.models.organisation import Organisation
from src.models.vulnerability import Vulnerability
from src.models.assessment import Assessment
from src.models.wazuh import WazuhConnection, WazuhAlert, CorrelationResult
from src.models.benchmark import BenchmarkRecord, IndustrySnapshot


# ─── Base model tests ────────────────────────────────────────────────────────

class TestBaseModel:
    """Tests for the SQLAlchemy base model."""

    def test_utcnow_returns_utc(self):
        """utcnow should return a timezone-aware UTC datetime."""
        now = utcnow()
        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc

    def test_utcnow_is_current(self):
        """utcnow should return approximately the current time."""
        before = datetime.now(timezone.utc)
        now = utcnow()
        after = datetime.now(timezone.utc)
        assert before <= now <= after

    def test_base_is_declarative(self):
        """Base should be a valid SQLAlchemy DeclarativeBase."""
        from sqlalchemy.orm import DeclarativeBase
        assert issubclass(Base, DeclarativeBase)


# ─── Organisation model tests ────────────────────────────────────────────────

class TestOrganisationModel:
    """Tests for the Organisation SQLAlchemy model."""

    def test_organisation_has_required_columns(self):
        """Organisation should have all required columns."""
        columns = {c.name for c in Organisation.__table__.columns}
        required = {"id", "name", "slug", "industry_sector", "domain", "description",
                     "overall_risk_score", "culture_score", "compliance_score",
                     "vulnerability_count", "remediation_velocity", "created_at", "updated_at"}
        assert required.issubset(columns)

    def test_organisation_tablename(self):
        """Organisation table should be named correctly."""
        assert Organisation.__tablename__ == "organisations"

    def test_organisation_repr(self):
        """Organisation repr should include slug."""
        org = Organisation()
        org.slug = "test-org"
        assert "test-org" in repr(org)


# ─── Vulnerability model tests ───────────────────────────────────────────────

class TestVulnerabilityModel:
    """Tests for the Vulnerability SQLAlchemy model."""

    def test_vulnerability_has_required_columns(self):
        """Vulnerability should have all required columns."""
        columns = {c.name for c in Vulnerability.__table__.columns}
        required = {"id", "org_id", "title", "severity", "cvss_score", "source", "status"}
        assert required.issubset(columns)

    def test_vulnerability_tablename(self):
        """Vulnerability table should be named correctly."""
        assert Vulnerability.__tablename__ == "vulnerabilities"


# ─── Wazuh model tests ──────────────────────────────────────────────────────

class TestWazuhModels:
    """Tests for Wazuh SQLAlchemy models."""

    def test_wazuh_connection_tablename(self):
        assert WazuhConnection.__tablename__ == "wazuh_connections"

    def test_wazuh_alert_tablename(self):
        assert WazuhAlert.__tablename__ == "wazuh_alerts"

    def test_correlation_result_tablename(self):
        assert CorrelationResult.__tablename__ == "correlation_results"

    def test_wazuh_alert_has_timestamp(self):
        columns = {c.name for c in WazuhAlert.__table__.columns}
        assert "timestamp" in columns

    def test_correlation_result_has_confidence(self):
        columns = {c.name for c in CorrelationResult.__table__.columns}
        assert "confidence" in columns


# ─── Benchmark model tests ──────────────────────────────────────────────────

class TestBenchmarkModels:
    """Tests for Benchmark SQLAlchemy models."""

    def test_benchmark_record_tablename(self):
        assert BenchmarkRecord.__tablename__ == "benchmark_records"

    def test_industry_snapshot_tablename(self):
        assert IndustrySnapshot.__tablename__ == "industry_snapshots"

    def test_benchmark_record_has_period(self):
        columns = {c.name for c in BenchmarkRecord.__table__.columns}
        assert "period" in columns

    def test_industry_snapshot_has_percentile_fields(self):
        columns = {c.name for c in IndustrySnapshot.__table__.columns}
        assert "p25_risk_score" in columns
        assert "p75_risk_score" in columns


# ─── Wazuh schema tests ─────────────────────────────────────────────────────

class TestWazuhSchemas:
    """Tests for Wazuh Pydantic schemas."""

    def test_connect_request_validates(self):
        """WazuhConnectRequest should validate required fields."""
        req = WazuhConnectRequest(
            org_id="test",
            api_url="https://wazuh.example.com:55000",
            api_user="admin",
            api_password="secret",
        )
        assert req.org_id == "test"
        assert req.verify_ssl is True  # default

    def test_connect_response_serialises(self):
        """WazuhConnectResponse should serialise correctly."""
        resp = WazuhConnectResponse(
            org_id="test",
            api_url="https://wazuh.example.com",
            is_active=True,
            message="Connected",
        )
        data = resp.model_dump()
        assert data["org_id"] == "test"
        assert data["is_active"] is True

    def test_correlation_request_defaults(self):
        """CorrelationRequest should have sensible defaults."""
        req = CorrelationRequest()
        assert req.time_range_hours == 24
        assert req.min_confidence == 0.5

    def test_correlation_request_validation(self):
        """CorrelationRequest should validate boundaries."""
        with pytest.raises(ValidationError):
            CorrelationRequest(time_range_hours=0)
        with pytest.raises(ValidationError):
            CorrelationRequest(min_confidence=2.0)

    def test_timeline_event_serialises(self):
        """TimelineEvent should serialise datetime fields correctly."""
        event = TimelineEvent(
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            event_type="authentication",
            severity="high",
            title="Test event",
        )
        data = event.model_dump()
        assert "timestamp" in data
        assert data["source"] == "wazuh"

    def test_alert_response_all_fields(self):
        """WazuhAlertResponse should accept all fields."""
        resp = WazuhAlertResponse(
            id="a1",
            wazuh_id="wz-001",
            rule_id="5710",
            rule_description="Test",
            rule_level=10,
            agent_name="srv",
            agent_ip="10.0.0.1",
            source_ip="1.2.3.4",
            destination_ip="10.0.0.1",
            category="authentication",
            plain_english="A test alert",
            timestamp=datetime.now(timezone.utc),
        )
        assert resp.rule_level == 10

    def test_correlate_result_serialises(self):
        """CorrelateResult should serialise correctly."""
        result = CorrelateResult(
            org_id="test",
            correlations_found=2,
            high_severity_count=1,
            correlations=[],
            summary="Test summary",
        )
        data = result.model_dump()
        assert data["correlations_found"] == 2


# ─── Benchmark schema tests ─────────────────────────────────────────────────

class TestBenchmarkSchemas:
    """Tests for Benchmark Pydantic schemas."""

    def test_metric_percentile_validation(self):
        """MetricPercentile should validate percentile range."""
        mp = MetricPercentile(
            metric="culture_score",
            value=75.0,
            percentile=80.0,
            industry_average=70.0,
            industry_median=72.0,
            interpretation="Above average",
        )
        assert mp.percentile == 80.0

    def test_metric_percentile_rejects_invalid_range(self):
        """MetricPercentile should reject percentile > 100."""
        with pytest.raises(ValidationError):
            MetricPercentile(
                metric="test",
                value=50,
                percentile=150,
                industry_average=50,
                industry_median=50,
                interpretation="Invalid",
            )

    def test_compare_request_defaults(self):
        """CompareRequest should have sensible defaults."""
        req = CompareRequest()
        assert req.periods == 6
        assert req.compare_sectors == []

    def test_compare_request_validation(self):
        """CompareRequest should validate period boundaries."""
        with pytest.raises(ValidationError):
            CompareRequest(periods=0)
        with pytest.raises(ValidationError):
            CompareRequest(periods=100)

    def test_trend_point_optional_change(self):
        """TrendPoint change_pct should be optional."""
        tp = TrendPoint(period="2025-01", value=50.0)
        assert tp.change_pct is None

    def test_trend_series_serialises(self):
        """TrendSeries should serialise completely."""
        ts = TrendSeries(
            metric="culture_score",
            data_points=[TrendPoint(period="2025-01", value=70.0)],
            direction="improving",
            interpretation="Getting better",
        )
        data = ts.model_dump()
        assert len(data["data_points"]) == 1

    def test_benchmark_position_serialises(self):
        """BenchmarkPosition should serialise all fields."""
        bp = BenchmarkPosition(
            org_id="test",
            industry_sector="technology",
            period="2025-12",
            overall_percentile=65.0,
            metrics=[],
            peer_count=10,
            summary="Test summary",
        )
        data = bp.model_dump()
        assert data["overall_percentile"] == 65.0

    def test_industry_stat_serialises(self):
        """IndustryStat should serialise all fields."""
        stat = IndustryStat(
            industry_sector="technology",
            period="2025-12",
            org_count=5,
            avg_vulnerability_count=15.0,
            avg_remediation_velocity=3.5,
            avg_culture_score=72.0,
            avg_compliance_score=80.0,
            avg_risk_score=55.0,
            median_vulnerability_count=12.0,
            p25_risk_score=40.0,
            p75_risk_score=70.0,
        )
        data = stat.model_dump()
        assert data["org_count"] == 5


# ─── Health schema tests ─────────────────────────────────────────────────────

class TestHealthSchemas:
    """Tests for Health Pydantic schemas."""

    def test_service_health_serialises(self):
        """ServiceHealth should serialise correctly."""
        sh = ServiceHealth(service="app", status="healthy", latency_ms=1.5)
        data = sh.model_dump()
        assert data["service"] == "app"
        assert data["latency_ms"] == 1.5

    def test_service_health_optional_details(self):
        """ServiceHealth details should be optional."""
        sh = ServiceHealth(service="db", status="unhealthy")
        assert sh.details is None

    def test_health_response_serialises(self):
        """HealthResponse should serialise correctly."""
        hr = HealthResponse(
            status="healthy",
            version="2.0.0",
            environment="development",
            services=[],
        )
        data = hr.model_dump()
        assert data["version"] == "2.0.0"

    def test_health_response_with_services(self):
        """HealthResponse should include service details."""
        hr = HealthResponse(
            status="degraded",
            version="2.0.0",
            environment="production",
            services=[
                ServiceHealth(service="app", status="healthy", latency_ms=1.0),
                ServiceHealth(service="db", status="unhealthy", details="Connection refused"),
            ],
        )
        assert len(hr.services) == 2
        assert hr.services[1].details == "Connection refused"


# ─── Assessment model tests ──────────────────────────────────────────────────

class TestAssessmentModel:
    """Tests for the Assessment SQLAlchemy model."""

    def test_assessment_has_required_columns(self):
        """Assessment should have severity count columns."""
        columns = {c.name for c in Assessment.__table__.columns}
        required = {"id", "org_id", "overall_score", "vulnerability_count",
                     "critical_count", "high_count", "medium_count", "low_count"}
        assert required.issubset(columns)

    def test_assessment_tablename(self):
        assert Assessment.__tablename__ == "assessments"
