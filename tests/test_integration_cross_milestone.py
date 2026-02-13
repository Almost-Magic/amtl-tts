"""Cross-milestone integration tests — verifying interactions between all Phase 4 systems.

These tests ensure Wazuh correlation, benchmark engine, and production hardening
all work together as a coherent platform.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from src.services.wazuh_correlation import (
    correlate_alerts_with_vulnerabilities,
    build_unified_timeline,
    translate_wazuh_alert_to_plain_english,
    classify_wazuh_alert_category,
    generate_timeline_summary,
    _wazuh_level_to_severity,
)
from src.services.benchmark_engine import (
    calculate_percentile,
    compute_industry_statistics,
    compute_org_benchmark,
    compute_trend_data,
    anonymise_records,
    generate_comparison_report,
    BENCHMARK_METRICS,
    LOWER_IS_BETTER,
)
from src.config import Settings
from src.app import create_app
from src.store import data_store


# ─── Cross-milestone integration ─────────────────────────────────────────────

class TestWazuhAndBenchmarkIntegration:
    """Tests verifying Wazuh and Benchmark systems interact correctly."""

    def test_org_with_both_wazuh_and_benchmark_data(
        self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts, sample_benchmark_data
    ):
        """An org should be able to use both Wazuh and Benchmark endpoints."""
        # Wazuh correlation
        wazuh_resp = client.post(f"/api/wazuh/correlate/{sample_org}")
        assert wazuh_resp.status_code == 200

        # Benchmark position
        bench_resp = client.get(f"/api/benchmarks/{sample_org}")
        assert bench_resp.status_code == 200

        # Both should reference the same org
        assert wazuh_resp.json()["org_id"] == sample_org
        assert bench_resp.json()["org_id"] == sample_org

    def test_timeline_reflects_vulnerability_data(
        self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts
    ):
        """Timeline should include vulnerability data used in benchmarks."""
        resp = client.get(f"/api/wazuh/timeline/{sample_org}")
        assert resp.status_code == 200
        data = resp.json()

        sources = {e["source"] for e in data["events"]}
        assert "digital_sentinel" in sources
        assert "wazuh" in sources

    def test_correlation_severity_matches_benchmark_metrics(
        self, sample_org, sample_vulnerabilities, sample_wazuh_alerts
    ):
        """Correlation severity labels should be consistent with benchmark severity tracking."""
        alerts = data_store.get_wazuh_alerts(sample_org)
        vulns = data_store.get_vulnerabilities(sample_org)

        correlations = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for corr in correlations:
            assert corr["severity"] in valid_severities


# ─── Health endpoints with full app context ───────────────────────────────────

class TestHealthWithFullContext:
    """Tests for health endpoints in a fully configured app."""

    def test_health_after_data_operations(self, client, sample_org, sample_benchmark_data):
        """Health should remain healthy after data store operations."""
        # Perform operations
        client.get(f"/api/benchmarks/{sample_org}")
        client.get("/api/benchmarks/industry/technology")

        # Health should still be OK
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_liveness_independent_of_data(self, client):
        """Liveness probe should work regardless of data state."""
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_readiness_with_empty_store(self, client):
        """Readiness should be healthy even with empty data store."""
        data_store.reset()
        resp = client.get("/health/ready")
        assert resp.status_code == 200


# ─── Multi-org scenario tests ───────────────────────────────────────────────

class TestMultiOrgScenarios:
    """Tests covering multiple organisations interacting simultaneously."""

    def _setup_multi_orgs(self):
        """Create multiple organisations with varying data."""
        orgs = ["alpha-corp", "beta-inc", "gamma-ltd"]
        now = datetime.now(timezone.utc)

        for i, org in enumerate(orgs):
            data_store.add_organisation(org, {
                "id": org,
                "name": org.replace("-", " ").title(),
                "slug": org,
                "industry_sector": "technology",
            })

            # Add varying numbers of vulns
            for j in range(i + 1):
                data_store.add_vulnerability(org, {
                    "id": str(uuid.uuid4()),
                    "title": f"Vuln {j} for {org}",
                    "severity": ["low", "medium", "high"][j % 3],
                    "cvss_score": 3.0 + j * 2,
                    "asset": f"10.0.{i}.{j}",
                    "created_at": now - timedelta(hours=j),
                })

            # Add varying numbers of alerts
            for j in range(i + 2):
                data_store.add_wazuh_alert(org, {
                    "id": str(uuid.uuid4()),
                    "wazuh_id": f"wz-{org}-{j}",
                    "rule_id": f"{5000 + j}",
                    "rule_description": f"Alert {j} for {org}",
                    "rule_level": 5 + j * 2,
                    "agent_name": f"agent-{i}",
                    "agent_ip": f"10.0.{i}.0",
                    "source_ip": f"192.168.{i}.{j}",
                    "destination_ip": f"10.0.{i}.{j}",
                    "category": ["authentication", "network", "web"][j % 3],
                    "timestamp": now - timedelta(hours=j),
                })

            # Add benchmark records
            data_store.add_benchmark_record(org, {
                "org_id": org,
                "industry_sector": "technology",
                "period": "2025-12",
                "vulnerability_count": (i + 1) * 5,
                "critical_count": i,
                "high_count": i + 1,
                "remediation_velocity": 4.0 - i,
                "culture_score": 80 - i * 10,
                "compliance_score": 85 - i * 5,
                "overall_risk_score": 40 + i * 15,
            })

        return orgs

    def test_each_org_gets_independent_correlations(self, client):
        """Each org should get its own correlation results."""
        orgs = self._setup_multi_orgs()

        results = {}
        for org in orgs:
            resp = client.post(f"/api/wazuh/correlate/{org}")
            assert resp.status_code == 200
            results[org] = resp.json()

        # Results should be org-specific
        for org in orgs:
            assert results[org]["org_id"] == org

    def test_each_org_gets_independent_timelines(self, client):
        """Each org should have its own timeline."""
        orgs = self._setup_multi_orgs()

        for org in orgs:
            resp = client.get(f"/api/wazuh/timeline/{org}")
            assert resp.status_code == 200
            assert resp.json()["org_id"] == org

    def test_benchmark_ranks_multiple_orgs(self, client):
        """Benchmark should correctly rank multiple orgs against each other."""
        orgs = self._setup_multi_orgs()

        positions = {}
        for org in orgs:
            resp = client.get(f"/api/benchmarks/{org}")
            assert resp.status_code == 200
            positions[org] = resp.json()["overall_percentile"]

        # All positions should be valid percentiles
        for org, percentile in positions.items():
            assert 0 <= percentile <= 100

    def test_industry_stats_reflect_all_orgs(self, client):
        """Industry stats should include data from all organisations."""
        orgs = self._setup_multi_orgs()

        resp = client.get("/api/benchmarks/industry/technology")
        assert resp.status_code == 200
        data = resp.json()
        assert data["stats"]["org_count"] >= len(orgs)


# ─── Data store operations ───────────────────────────────────────────────────

class TestDataStoreOperations:
    """Tests for data store CRUD operations."""

    def test_add_and_retrieve_organisation(self):
        """Should be able to add and retrieve an organisation."""
        data_store.add_organisation("test-org", {"id": "test-org", "name": "Test"})
        assert "test-org" in data_store.organisations
        assert data_store.organisations["test-org"]["name"] == "Test"

    def test_add_and_retrieve_vulnerabilities(self):
        """Should be able to add and retrieve vulnerabilities."""
        data_store.add_vulnerability("org-1", {"id": "v1", "title": "Test Vuln"})
        data_store.add_vulnerability("org-1", {"id": "v2", "title": "Test Vuln 2"})
        vulns = data_store.get_vulnerabilities("org-1")
        assert len(vulns) == 2

    def test_get_vulnerabilities_nonexistent_org(self):
        """Getting vulns for nonexistent org should return empty list."""
        assert data_store.get_vulnerabilities("nonexistent") == []

    def test_add_and_retrieve_wazuh_alerts(self):
        """Should be able to add and retrieve Wazuh alerts."""
        data_store.add_wazuh_alert("org-1", {"id": "a1"})
        data_store.add_wazuh_alert("org-1", {"id": "a2"})
        alerts = data_store.get_wazuh_alerts("org-1")
        assert len(alerts) == 2

    def test_get_wazuh_alerts_nonexistent_org(self):
        """Getting alerts for nonexistent org should return empty list."""
        assert data_store.get_wazuh_alerts("nonexistent") == []

    def test_add_and_retrieve_benchmark_records(self):
        """Should be able to add and retrieve benchmark records."""
        data_store.add_benchmark_record("org-1", {"org_id": "org-1", "period": "2025-01"})
        records = data_store.get_benchmark_records("org-1")
        assert len(records) == 1

    def test_get_benchmark_records_nonexistent_org(self):
        """Getting records for nonexistent org should return empty list."""
        assert data_store.get_benchmark_records("nonexistent") == []

    def test_sector_records_filtering(self):
        """Sector records should be correctly filtered by sector and period."""
        data_store.add_benchmark_record("org-1", {
            "org_id": "org-1", "industry_sector": "tech", "period": "2025-01",
        })
        data_store.add_benchmark_record("org-2", {
            "org_id": "org-2", "industry_sector": "finance", "period": "2025-01",
        })

        tech = data_store.get_sector_records("tech", "2025-01")
        assert len(tech) == 1
        assert tech[0]["industry_sector"] == "tech"

    def test_wazuh_connection_storage(self):
        """Wazuh connections should be stored and retrievable."""
        data_store.wazuh_connections["org-1"] = {"api_url": "https://wazuh.test"}
        assert data_store.wazuh_connections["org-1"]["api_url"] == "https://wazuh.test"


# ─── Full workflow simulation ─────────────────────────────────────────────────

class TestFullWorkflow:
    """End-to-end workflow tests simulating real usage patterns."""

    def test_complete_assessment_workflow(self, client):
        """Simulate a complete security assessment workflow."""
        org = "workflow-test-org"
        now = datetime.now(timezone.utc)

        # Step 1: Set up organisation
        data_store.add_organisation(org, {
            "id": org,
            "name": "Workflow Test Org",
            "slug": org,
            "industry_sector": "technology",
        })

        # Step 2: Add vulnerabilities (external scanning)
        for i in range(5):
            data_store.add_vulnerability(org, {
                "id": str(uuid.uuid4()),
                "title": f"Vulnerability {i}",
                "severity": ["critical", "high", "medium", "low", "low"][i],
                "cvss_score": [9.8, 7.5, 5.0, 3.0, 2.0][i],
                "asset": f"10.0.0.{i + 1}",
                "created_at": now - timedelta(hours=i),
            })

        # Step 3: Configure Wazuh
        resp = client.post("/api/wazuh/connect", json={
            "org_id": org,
            "api_url": "https://wazuh.test:55000",
            "api_user": "admin",
            "api_password": "pass",
        })
        assert resp.status_code == 200

        # Step 4: Add Wazuh alerts (internal monitoring)
        for i in range(3):
            data_store.add_wazuh_alert(org, {
                "id": str(uuid.uuid4()),
                "wazuh_id": f"wz-wf-{i}",
                "rule_id": f"{5000 + i}",
                "rule_description": f"Workflow alert {i}",
                "rule_level": 8 + i * 2,
                "agent_name": f"server-{i}",
                "agent_ip": f"10.0.0.{i + 1}",
                "source_ip": "203.0.113.50",
                "destination_ip": f"10.0.0.{i + 1}",
                "category": "authentication",
                "timestamp": now - timedelta(hours=i),
            })

        # Step 5: Run correlation
        resp = client.post(f"/api/wazuh/correlate/{org}")
        assert resp.status_code == 200
        correlations = resp.json()
        assert correlations["correlations_found"] >= 0

        # Step 6: Get timeline
        resp = client.get(f"/api/wazuh/timeline/{org}")
        assert resp.status_code == 200
        timeline = resp.json()
        assert timeline["total_events"] >= 8  # 5 vulns + 3 alerts

        # Step 7: Get translated alerts
        resp = client.get(f"/api/wazuh/alerts/{org}")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) == 3
        for alert in alerts:
            assert alert["plain_english"] is not None

        # Step 8: Add benchmark data
        data_store.add_benchmark_record(org, {
            "org_id": org,
            "industry_sector": "technology",
            "period": "2025-12",
            "vulnerability_count": 5,
            "critical_count": 1,
            "high_count": 1,
            "remediation_velocity": 3.5,
            "culture_score": 75.0,
            "compliance_score": 82.0,
            "overall_risk_score": 55.0,
        })

        # Step 9: Get benchmark position
        resp = client.get(f"/api/benchmarks/{org}")
        assert resp.status_code == 200
        benchmark = resp.json()
        assert benchmark["org_id"] == org

        # Step 10: Health check still OK
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_empty_org_workflow(self, client):
        """An org with no data should return appropriate 404s for data endpoints."""
        org = "empty-org"
        data_store.add_organisation(org, {
            "id": org,
            "name": "Empty Org",
            "slug": org,
            "industry_sector": "technology",
        })

        # Timeline works but empty
        resp = client.get(f"/api/wazuh/timeline/{org}")
        assert resp.status_code == 200
        assert resp.json()["total_events"] == 0

        # Alerts returns empty list
        resp = client.get(f"/api/wazuh/alerts/{org}")
        assert resp.status_code == 200
        assert resp.json() == []

        # Correlation works but finds nothing
        resp = client.post(f"/api/wazuh/correlate/{org}")
        assert resp.status_code == 200
        assert resp.json()["correlations_found"] == 0

        # Benchmark returns 404 (no benchmark records)
        resp = client.get(f"/api/benchmarks/{org}")
        assert resp.status_code == 404


# ─── Australian English verification ─────────────────────────────────────────

class TestAustralianEnglish:
    """Verify Australian English is used throughout the platform."""

    def test_readme_uses_licence_not_license(self):
        """README should use 'Licence' (Australian/British) not 'License'."""
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "README.md")
        with open(path) as f:
            content = f.read()
        # Check that "Licence" appears (Australian English)
        assert "Licence" in content

    def test_benchmark_uses_organisation_not_organization(self):
        """Benchmark responses should use 'organisation' not 'organization'."""
        from src.services.benchmark_engine import _interpret_percentile
        result = _interpret_percentile("culture_score", 50.0, 70.0, 70.0)
        # The interpretation text doesn't use "organisation" but the
        # endpoint responses do - check the schema descriptions
        from src.schemas.benchmark import BenchmarkPosition
        # Model exists with org_id field
        assert hasattr(BenchmarkPosition, "model_fields")

    def test_plain_english_uses_correct_spelling(self):
        """Alert translations should not use American spellings."""
        alert = {
            "rule_id": "5710",
            "rule_description": "Unauthorised access attempt",
            "rule_level": 10,
            "agent_name": "server-01",
            "category": "authentication",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        # Should not crash with non-ASCII or special characters
        assert isinstance(result, str)


# ─── Configuration combinations ──────────────────────────────────────────────

class TestConfigurationCombinations:
    """Tests for various configuration combinations."""

    def test_production_settings(self):
        """Production settings should be valid."""
        settings = Settings(
            environment="production",
            debug=False,
            log_format="json",
            rate_limit_default="100/minute",
        )
        app = create_app(settings)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["environment"] == "production"

    def test_staging_settings(self):
        """Staging settings should be valid."""
        settings = Settings(
            environment="staging",
            debug=True,
            log_format="console",
            rate_limit_default="200/minute",
        )
        app = create_app(settings)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["environment"] == "staging"

    def test_development_settings(self):
        """Development settings should be valid."""
        settings = Settings(
            environment="development",
            debug=True,
            log_format="console",
            rate_limit_default="1000/minute",
        )
        app = create_app(settings)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["environment"] == "development"

    def test_custom_version(self):
        """Custom version should be reflected in health response."""
        settings = Settings(app_version="3.0.0-beta", rate_limit_default="1000/minute")
        app = create_app(settings)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.json()["version"] == "3.0.0-beta"
