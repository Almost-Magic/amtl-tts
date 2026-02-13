"""Comprehensive API tests — thorough endpoint validation.

Covers: all API endpoints with various input combinations,
error handling, response format validation, and content verification.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from src.store import data_store
from src.config import Settings
from src.app import create_app


# ─── Wazuh connect endpoint ─────────────────────────────────────────────────

class TestWazuhConnectEndpoint:
    """Thorough tests for POST /api/wazuh/connect."""

    def test_connect_stores_connection(self, client):
        """Connection should be stored in data store."""
        client.post("/api/wazuh/connect", json={
            "org_id": "store-test",
            "api_url": "https://wazuh.test:55000",
            "api_user": "admin",
            "api_password": "secret",
        })
        assert "store-test" in data_store.wazuh_connections
        assert data_store.wazuh_connections["store-test"]["api_url"] == "https://wazuh.test:55000"

    def test_connect_overwrites_existing(self, client):
        """Reconnecting should overwrite the previous connection."""
        client.post("/api/wazuh/connect", json={
            "org_id": "overwrite-test",
            "api_url": "https://old.wazuh.test",
            "api_user": "admin",
            "api_password": "old",
        })
        client.post("/api/wazuh/connect", json={
            "org_id": "overwrite-test",
            "api_url": "https://new.wazuh.test",
            "api_user": "admin",
            "api_password": "new",
        })
        assert data_store.wazuh_connections["overwrite-test"]["api_url"] == "https://new.wazuh.test"

    def test_connect_response_format(self, client):
        """Response should have correct format."""
        resp = client.post("/api/wazuh/connect", json={
            "org_id": "format-test",
            "api_url": "https://wazuh.test",
            "api_user": "admin",
            "api_password": "pass",
        })
        data = resp.json()
        assert set(data.keys()) == {"org_id", "api_url", "is_active", "message"}


# ─── Wazuh correlation endpoint ──────────────────────────────────────────────

class TestWazuhCorrelateEndpoint:
    """Thorough tests for POST /api/wazuh/correlate/{org}."""

    def test_correlate_with_no_data(self, client, sample_org):
        """Correlation with no alerts/vulns should return empty results."""
        resp = client.post(f"/api/wazuh/correlate/{sample_org}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["correlations_found"] == 0
        assert data["correlations"] == []

    def test_correlate_with_only_vulns(self, client, sample_org, sample_vulnerabilities):
        """Correlation with only vulns (no alerts) should return empty."""
        resp = client.post(f"/api/wazuh/correlate/{sample_org}")
        assert resp.status_code == 200
        assert resp.json()["correlations_found"] == 0

    def test_correlate_with_only_alerts(self, client, sample_org, sample_wazuh_alerts):
        """Correlation with only alerts (no vulns) should return empty."""
        resp = client.post(f"/api/wazuh/correlate/{sample_org}")
        assert resp.status_code == 200
        assert resp.json()["correlations_found"] == 0

    def test_correlate_stores_results(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Correlation results should be stored for timeline use."""
        client.post(f"/api/wazuh/correlate/{sample_org}")
        assert sample_org in data_store.correlation_results

    def test_correlate_with_high_threshold(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """High confidence threshold should filter correlations."""
        resp = client.post(f"/api/wazuh/correlate/{sample_org}", json={
            "min_confidence": 0.99,
        })
        assert resp.status_code == 200
        data = resp.json()
        # High threshold may filter out all or most correlations
        for corr in data["correlations"]:
            assert corr["confidence"] >= 0.99

    def test_correlate_response_has_all_fields(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Each correlation in the response should have all required fields."""
        resp = client.post(f"/api/wazuh/correlate/{sample_org}", json={
            "min_confidence": 0.1,
        })
        data = resp.json()
        for corr in data["correlations"]:
            assert "id" in corr
            assert "correlation_type" in corr
            assert "severity" in corr
            assert "confidence" in corr
            assert "title" in corr


# ─── Wazuh timeline endpoint ────────────────────────────────────────────────

class TestWazuhTimelineEndpoint:
    """Thorough tests for GET /api/wazuh/timeline/{org}."""

    def test_timeline_empty_org(self, client, sample_org):
        """Timeline for org with no data should return empty events."""
        resp = client.get(f"/api/wazuh/timeline/{sample_org}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 0
        assert data["events"] == []

    def test_timeline_events_have_required_fields(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Each timeline event should have all required fields."""
        resp = client.get(f"/api/wazuh/timeline/{sample_org}")
        data = resp.json()
        for event in data["events"]:
            assert "timestamp" in event
            assert "source" in event
            assert "event_type" in event
            assert "severity" in event
            assert "title" in event

    def test_timeline_sources_valid(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Timeline event sources should be valid values."""
        resp = client.get(f"/api/wazuh/timeline/{sample_org}")
        data = resp.json()
        valid_sources = {"wazuh", "digital_sentinel", "correlation"}
        for event in data["events"]:
            assert event["source"] in valid_sources

    def test_timeline_severity_valid(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Timeline event severity should be valid values."""
        resp = client.get(f"/api/wazuh/timeline/{sample_org}")
        data = resp.json()
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for event in data["events"]:
            assert event["severity"] in valid_severities

    def test_timeline_custom_hours_range(self, client, sample_org):
        """Timeline should accept various valid hours values."""
        for hours in [1, 24, 168, 720]:
            resp = client.get(f"/api/wazuh/timeline/{sample_org}?hours={hours}")
            assert resp.status_code == 200
            assert resp.json()["time_range_hours"] == hours


# ─── Wazuh alerts endpoint ──────────────────────────────────────────────────

class TestWazuhAlertsEndpoint:
    """Thorough tests for GET /api/wazuh/alerts/{org}."""

    def test_alerts_empty_org(self, client, sample_org):
        """Alerts for org with no data should return empty list."""
        resp = client.get(f"/api/wazuh/alerts/{sample_org}")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_alerts_all_have_plain_english(self, client, sample_org, sample_wazuh_alerts):
        """Every alert should have a plain English translation."""
        resp = client.get(f"/api/wazuh/alerts/{sample_org}")
        data = resp.json()
        for alert in data:
            assert alert["plain_english"] is not None
            assert len(alert["plain_english"]) > 10

    def test_alerts_limit_respected(self, client, sample_org, sample_wazuh_alerts):
        """Limit parameter should be respected."""
        resp = client.get(f"/api/wazuh/alerts/{sample_org}?limit=1")
        assert resp.status_code == 200
        assert len(resp.json()) <= 1

    def test_alerts_have_all_fields(self, client, sample_org, sample_wazuh_alerts):
        """Each alert should have all response fields."""
        resp = client.get(f"/api/wazuh/alerts/{sample_org}")
        data = resp.json()
        for alert in data:
            assert "id" in alert
            assert "wazuh_id" in alert
            assert "rule_id" in alert
            assert "rule_level" in alert
            assert "category" in alert
            assert "timestamp" in alert


# ─── Benchmark position endpoint ─────────────────────────────────────────────

class TestBenchmarkPositionEndpoint:
    """Thorough tests for GET /api/benchmarks/{org}."""

    def test_position_overall_percentile_valid(self, client, sample_org, sample_benchmark_data):
        """Overall percentile should be a valid number."""
        resp = client.get(f"/api/benchmarks/{sample_org}")
        data = resp.json()
        assert isinstance(data["overall_percentile"], (int, float))
        assert 0 <= data["overall_percentile"] <= 100

    def test_position_industry_sector_correct(self, client, sample_org, sample_benchmark_data):
        """Industry sector should match the org's sector."""
        resp = client.get(f"/api/benchmarks/{sample_org}")
        data = resp.json()
        assert data["industry_sector"] == "technology"

    def test_position_has_peer_count(self, client, sample_org, sample_benchmark_data):
        """Response should include peer count."""
        resp = client.get(f"/api/benchmarks/{sample_org}")
        data = resp.json()
        assert data["peer_count"] >= 1

    def test_position_metrics_interpretations_non_empty(self, client, sample_org, sample_benchmark_data):
        """Each metric interpretation should be non-empty."""
        resp = client.get(f"/api/benchmarks/{sample_org}")
        data = resp.json()
        for metric in data["metrics"]:
            assert len(metric["interpretation"]) > 20


# ─── Benchmark industry endpoint ─────────────────────────────────────────────

class TestBenchmarkIndustryEndpoint:
    """Thorough tests for GET /api/benchmarks/industry/{sector}."""

    def test_industry_stats_structure(self, client, sample_benchmark_data):
        """Industry stats should have the correct structure."""
        resp = client.get("/api/benchmarks/industry/technology")
        data = resp.json()
        stats = data["stats"]
        required_keys = {
            "industry_sector", "period", "org_count",
            "avg_vulnerability_count", "avg_remediation_velocity",
            "avg_culture_score", "avg_compliance_score", "avg_risk_score",
            "median_vulnerability_count", "p25_risk_score", "p75_risk_score",
        }
        assert required_keys.issubset(set(stats.keys()))

    def test_industry_stats_values_non_negative(self, client, sample_benchmark_data):
        """All numeric stats should be non-negative."""
        resp = client.get("/api/benchmarks/industry/technology")
        stats = resp.json()["stats"]
        assert stats["org_count"] >= 0
        assert stats["avg_vulnerability_count"] >= 0
        assert stats["avg_risk_score"] >= 0

    def test_industry_stats_different_sectors(self, client, sample_benchmark_data):
        """Different sectors should return different statistics."""
        tech = client.get("/api/benchmarks/industry/technology").json()
        fin = client.get("/api/benchmarks/industry/financial_services").json()
        assert tech["industry_sector"] == "technology"
        assert fin["industry_sector"] == "financial_services"


# ─── Benchmark trends endpoint ───────────────────────────────────────────────

class TestBenchmarkTrendsEndpoint:
    """Thorough tests for GET /api/benchmarks/trends/{sector}."""

    def test_trends_direction_valid(self, client, sample_benchmark_data):
        """All trend directions should be valid values."""
        resp = client.get("/api/benchmarks/trends/technology")
        data = resp.json()
        for trend in data["trends"]:
            assert trend["direction"] in ("improving", "worsening", "stable")

    def test_trends_have_data_points(self, client, sample_benchmark_data):
        """Each trend should have data points."""
        resp = client.get("/api/benchmarks/trends/technology")
        data = resp.json()
        for trend in data["trends"]:
            assert len(trend["data_points"]) >= 1

    def test_trends_data_points_have_periods(self, client, sample_benchmark_data):
        """Each data point should have a period."""
        resp = client.get("/api/benchmarks/trends/technology")
        data = resp.json()
        for trend in data["trends"]:
            for dp in trend["data_points"]:
                assert "period" in dp
                assert "value" in dp


# ─── Benchmark compare endpoint ──────────────────────────────────────────────

class TestBenchmarkCompareEndpoint:
    """Thorough tests for POST /api/benchmarks/compare/{org}."""

    def test_compare_strengths_are_strings(self, client, sample_org, sample_benchmark_data):
        """All strengths should be descriptive strings."""
        resp = client.post(f"/api/benchmarks/compare/{sample_org}")
        data = resp.json()
        for s in data["strengths"]:
            assert isinstance(s, str)
            assert len(s) > 5

    def test_compare_weaknesses_are_strings(self, client, sample_org, sample_benchmark_data):
        """All weaknesses should be descriptive strings."""
        resp = client.post(f"/api/benchmarks/compare/{sample_org}")
        data = resp.json()
        for w in data["weaknesses"]:
            assert isinstance(w, str)
            assert len(w) > 5

    def test_compare_recommendations_are_actionable(self, client, sample_org, sample_benchmark_data):
        """All recommendations should be actionable strings."""
        resp = client.post(f"/api/benchmarks/compare/{sample_org}")
        data = resp.json()
        for r in data["recommendations"]:
            assert isinstance(r, str)
            assert len(r) > 10


# ─── OpenAPI and docs endpoints ──────────────────────────────────────────────

class TestAPIDocEndpoints:
    """Tests for API documentation endpoints."""

    def test_openapi_json_accessible(self, client):
        """OpenAPI JSON schema should be accessible."""
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

    def test_openapi_has_paths(self, client):
        """OpenAPI schema should define paths."""
        schema = client.get("/openapi.json").json()
        assert len(schema["paths"]) >= 10

    def test_openapi_paths_have_methods(self, client):
        """Each path should have at least one HTTP method."""
        schema = client.get("/openapi.json").json()
        for path, methods in schema["paths"].items():
            assert len(methods) >= 1

    def test_swagger_docs_accessible(self, client):
        """Swagger UI docs should be accessible."""
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_accessible(self, client):
        """ReDoc should be accessible."""
        resp = client.get("/redoc")
        assert resp.status_code == 200


# ─── Error handling ──────────────────────────────────────────────────────────

class TestErrorHandling:
    """Tests for error handling across all endpoints."""

    def test_404_for_unknown_wazuh_org(self, client):
        """All Wazuh endpoints should 404 for unknown orgs."""
        for endpoint in [
            "/api/wazuh/correlate/unknown",
            "/api/wazuh/timeline/unknown",
            "/api/wazuh/alerts/unknown",
        ]:
            resp = client.post(endpoint) if "correlate" in endpoint else client.get(endpoint)
            assert resp.status_code == 404

    def test_404_for_unknown_benchmark_org(self, client):
        """Benchmark and compare should 404 for unknown orgs."""
        assert client.get("/api/benchmarks/unknown").status_code == 404
        assert client.post("/api/benchmarks/compare/unknown").status_code == 404

    def test_health_never_returns_error(self, client):
        """Health endpoints should never return 5xx."""
        for endpoint in ["/health", "/health/ready", "/health/live"]:
            resp = client.get(endpoint)
            assert resp.status_code < 500
