"""Stress and boundary tests — pushing the platform to its limits.

Covers: large data volumes, boundary values, concurrent-style access patterns,
performance characteristics, and robustness under edge conditions.
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
    _calculate_correlation_confidence,
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
)
from src.store import data_store, DataStore


# ─── Large volume correlation tests ─────────────────────────────────────────

class TestLargeVolumeCorrelation:
    """Tests with large data volumes for the correlation engine."""

    def test_correlate_100_alerts_100_vulns(self):
        """Correlation should handle 100 alerts x 100 vulnerabilities."""
        now = datetime.now(timezone.utc)
        alerts = [
            {
                "wazuh_id": f"wz-{i}",
                "rule_id": f"{5000 + i % 100}",
                "rule_description": f"Alert {i}",
                "rule_level": (i % 15) + 1,
                "agent_name": f"agent-{i % 10}",
                "agent_ip": f"10.0.{i // 256}.{i % 256}",
                "source_ip": f"192.168.{i // 256}.{i % 256}",
                "destination_ip": f"10.0.{i // 256}.{i % 256}",
                "category": ["authentication", "network", "web", "intrusion_detection"][i % 4],
                "timestamp": now - timedelta(minutes=i),
            }
            for i in range(100)
        ]
        vulns = [
            {
                "id": f"v-{i}",
                "title": f"Vulnerability {i}",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "cvss_score": float((i % 10) + 1),
                "asset": f"10.0.{i // 256}.{i % 256}",
            }
            for i in range(100)
        ]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        assert isinstance(results, list)
        # Should produce correlations given IP overlaps
        assert len(results) >= 1
        # All results should have required fields
        for r in results:
            assert "id" in r
            assert "severity" in r
            assert "confidence" in r

    def test_correlate_500_alerts_50_vulns(self):
        """Correlation should handle 500 alerts efficiently."""
        now = datetime.now(timezone.utc)
        alerts = [
            {
                "wazuh_id": f"wz-{i}",
                "rule_id": "5710",
                "rule_description": "Brute force",
                "rule_level": 10,
                "agent_name": "server",
                "agent_ip": "10.0.0.1",
                "source_ip": f"192.168.1.{i % 256}",
                "destination_ip": "10.0.0.1",
                "category": "authentication",
                "timestamp": now - timedelta(seconds=i),
            }
            for i in range(500)
        ]
        vulns = [
            {
                "id": f"v-{i}",
                "title": f"Vuln {i}",
                "severity": "high",
                "cvss_score": 7.5,
                "asset": "10.0.0.1",
            }
            for i in range(50)
        ]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        assert isinstance(results, list)

    def test_timeline_1000_events(self):
        """Timeline should handle 1000 events."""
        now = datetime.now(timezone.utc)
        alerts = [
            {
                "wazuh_id": f"wz-{i}",
                "rule_description": f"Alert {i}",
                "rule_level": 5,
                "category": "web",
                "timestamp": now - timedelta(seconds=i),
            }
            for i in range(500)
        ]
        vulns = [
            {
                "id": f"v-{i}",
                "title": f"Vuln {i}",
                "severity": "medium",
                "created_at": now - timedelta(seconds=i * 2),
            }
            for i in range(500)
        ]

        events = build_unified_timeline(alerts, vulns, [])
        assert len(events) == 1000
        summary = generate_timeline_summary(events)
        assert "1000" in summary or "500" in summary


# ─── Boundary value tests ────────────────────────────────────────────────────

class TestBoundaryValues:
    """Tests at boundary values for all parameters."""

    # Wazuh alert levels
    @pytest.mark.parametrize("level", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    def test_every_wazuh_level(self, level):
        """Every Wazuh alert level 0-15 should map to a valid severity."""
        severity = _wazuh_level_to_severity(level)
        assert severity in ("critical", "high", "medium", "low", "info")

    # Confidence boundaries
    @pytest.mark.parametrize("level,severity,cvss,expected_min", [
        (0, "low", 0.0, 0.0),
        (15, "critical", 10.0, 0.7),
        (7, "medium", 5.0, 0.3),
        (1, "info", 0.0, 0.0),
    ])
    def test_confidence_boundaries(self, level, severity, cvss, expected_min):
        """Confidence should behave correctly at boundary values."""
        alert = {"rule_level": level}
        vuln = {"severity": severity, "cvss_score": cvss}
        confidence = _calculate_correlation_confidence(alert, vuln)
        assert 0.0 <= confidence <= 1.0
        assert confidence >= expected_min

    # Percentile boundaries
    @pytest.mark.parametrize("value,expected_min,expected_max", [
        (0, 0, 20),
        (50, 40, 60),
        (100, 80, 100),
    ])
    def test_percentile_boundaries(self, value, expected_min, expected_max):
        """Percentile should be in expected range for boundary values."""
        values = list(range(101))  # 0-100
        p = calculate_percentile(value, values, lower_is_better=False)
        assert expected_min <= p <= expected_max

    # Alert classification edge cases
    @pytest.mark.parametrize("desc,expected_category", [
        ("", "general"),
        ("a", "general"),
        ("login failed authentication error", "authentication"),
        ("IDS ALERT INTRUSION DETECTED ATTACK", "intrusion_detection"),
        ("firewall blocked iptables denied", "firewall"),
    ])
    def test_classification_boundary_descriptions(self, desc, expected_category):
        """Classification should handle various description patterns."""
        result = classify_wazuh_alert_category("1000", desc, 3)
        assert result == expected_category


# ─── Data store stress tests ─────────────────────────────────────────────────

class TestDataStoreStress:
    """Stress tests for the data store."""

    def test_store_1000_orgs(self):
        """Store should handle 1000 organisations."""
        store = DataStore()
        for i in range(1000):
            store.add_organisation(f"org-{i}", {"id": f"org-{i}", "name": f"Org {i}"})
        assert len(store.organisations) == 1000

    def test_store_10000_vulnerabilities(self):
        """Store should handle 10000 vulnerabilities across orgs."""
        store = DataStore()
        for i in range(100):
            for j in range(100):
                store.add_vulnerability(f"org-{i}", {"id": f"v-{i}-{j}"})
        total = sum(len(v) for v in store.vulnerabilities.values())
        assert total == 10000

    def test_store_reset_clears_large_dataset(self):
        """Reset should clear even large datasets."""
        store = DataStore()
        for i in range(500):
            store.add_organisation(f"org-{i}", {"id": f"org-{i}"})
            store.add_vulnerability(f"org-{i}", {"id": f"v-{i}"})
            store.add_wazuh_alert(f"org-{i}", {"id": f"a-{i}"})
            store.add_benchmark_record(f"org-{i}", {"org_id": f"org-{i}"})

        store.reset()
        assert len(store.organisations) == 0
        assert len(store.vulnerabilities) == 0
        assert len(store.wazuh_alerts) == 0
        assert len(store.benchmark_records) == 0

    def test_sector_records_with_many_periods(self):
        """Sector record retrieval should work with many periods."""
        store = DataStore()
        for month in range(1, 13):
            for org_num in range(10):
                store.add_benchmark_record(f"org-{org_num}", {
                    "org_id": f"org-{org_num}",
                    "industry_sector": "technology",
                    "period": f"2025-{month:02d}",
                    "vulnerability_count": org_num + month,
                })

        by_period = store.get_sector_records_by_period("technology")
        assert len(by_period) == 12  # 12 months
        for period, records in by_period.items():
            assert len(records) == 10  # 10 orgs per period


# ─── Benchmark with large datasets ──────────────────────────────────────────

class TestBenchmarkLargeDatasets:
    """Tests for benchmark engine with large datasets."""

    def test_industry_stats_100_orgs(self):
        """Industry stats should handle 100 organisations."""
        records = [
            {
                "org_id": f"org-{i}",
                "vulnerability_count": i * 2,
                "remediation_velocity": float(i % 10),
                "culture_score": 50.0 + (i % 50),
                "compliance_score": 60.0 + (i % 40),
                "overall_risk_score": float(i % 100),
            }
            for i in range(100)
        ]
        stats = compute_industry_statistics(records)
        assert stats["org_count"] == 100
        assert stats["avg_vulnerability_count"] > 0
        assert stats["p25_risk_score"] <= stats["p75_risk_score"]

    def test_trend_data_24_periods(self):
        """Trend computation should handle 24 periods of data."""
        records_by_period = {}
        for month in range(1, 25):
            period = f"2024-{month:02d}" if month <= 12 else f"2025-{month - 12:02d}"
            records_by_period[period] = [
                {
                    "vulnerability_count": max(0, 100 - month * 3),
                    "culture_score": 50 + month * 2,
                    "overall_risk_score": max(0, 80 - month * 2.5),
                }
                for _ in range(10)
            ]

        trends = compute_trend_data(records_by_period)
        assert len(trends) == len(BENCHMARK_METRICS)
        for trend in trends:
            assert len(trend["data_points"]) == 24

    def test_org_benchmark_among_50_peers(self):
        """Org benchmark should work with 50 peers."""
        org_record = {
            "vulnerability_count": 15,
            "critical_count": 2,
            "high_count": 5,
            "remediation_velocity": 3.5,
            "culture_score": 72.0,
            "compliance_score": 80.0,
            "overall_risk_score": 65.0,
        }
        all_records = [
            {
                "vulnerability_count": i * 3,
                "critical_count": i % 5,
                "high_count": i * 2,
                "remediation_velocity": float(i % 8),
                "culture_score": 40.0 + i * 2,
                "compliance_score": 50.0 + i * 2,
                "overall_risk_score": float(i * 4),
            }
            for i in range(50)
        ] + [org_record]

        metrics = compute_org_benchmark(org_record, all_records)
        assert len(metrics) == len(BENCHMARK_METRICS)
        for m in metrics:
            assert 0 <= m["percentile"] <= 100


# ─── API stress tests ────────────────────────────────────────────────────────

class TestAPIStress:
    """Stress tests for API endpoints."""

    def test_rapid_health_checks(self, client):
        """Multiple rapid health checks should all succeed."""
        for _ in range(50):
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"

    def test_rapid_liveness_checks(self, client):
        """Multiple rapid liveness checks should all succeed."""
        for _ in range(100):
            resp = client.get("/health/live")
            assert resp.status_code == 200

    def test_sequential_wazuh_operations(self, client):
        """Sequential Wazuh operations should not interfere."""
        now = datetime.now(timezone.utc)

        for i in range(10):
            org = f"stress-org-{i}"
            data_store.add_organisation(org, {
                "id": org, "name": f"Stress Org {i}", "slug": org,
                "industry_sector": "technology",
            })
            data_store.add_vulnerability(org, {
                "id": str(uuid.uuid4()),
                "title": f"Vuln for {org}",
                "severity": "medium",
                "cvss_score": 5.0,
                "asset": f"10.0.{i}.1",
                "created_at": now,
            })
            data_store.add_wazuh_alert(org, {
                "id": str(uuid.uuid4()),
                "wazuh_id": f"wz-stress-{i}",
                "rule_id": "5710",
                "rule_description": "Test",
                "rule_level": 8,
                "agent_name": f"srv-{i}",
                "agent_ip": f"10.0.{i}.1",
                "source_ip": "1.2.3.4",
                "destination_ip": f"10.0.{i}.1",
                "category": "authentication",
                "timestamp": now,
            })

            resp = client.post(f"/api/wazuh/correlate/{org}")
            assert resp.status_code == 200

            resp = client.get(f"/api/wazuh/timeline/{org}")
            assert resp.status_code == 200

    def test_sequential_benchmark_operations(self, client):
        """Sequential benchmark operations should not interfere."""
        for i in range(10):
            org = f"bench-stress-{i}"
            data_store.add_organisation(org, {
                "id": org, "name": f"Bench Stress {i}", "slug": org,
                "industry_sector": "technology",
            })
            data_store.add_benchmark_record(org, {
                "org_id": org,
                "industry_sector": "technology",
                "period": "2025-12",
                "vulnerability_count": i * 5,
                "critical_count": i,
                "high_count": i + 1,
                "remediation_velocity": float(i),
                "culture_score": 50.0 + i * 5,
                "compliance_score": 60.0 + i * 3,
                "overall_risk_score": 40.0 + i * 5,
            })

            resp = client.get(f"/api/benchmarks/{org}")
            assert resp.status_code == 200


# ─── Translation edge cases ──────────────────────────────────────────────────

class TestTranslationEdgeCases:
    """Edge cases in alert translation."""

    def test_empty_agent_name(self):
        """Missing agent name should use fallback."""
        alert = {
            "rule_id": "1000",
            "rule_description": "Test",
            "rule_level": 5,
            "category": "general",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert "unknown" in result.lower()

    def test_very_long_description(self):
        """Very long descriptions should be handled."""
        alert = {
            "rule_id": "1000",
            "rule_description": "A" * 1000,
            "rule_level": 5,
            "agent_name": "server",
            "category": "general",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)

    def test_unicode_in_description(self):
        """Unicode characters in descriptions should be handled."""
        alert = {
            "rule_id": "1000",
            "rule_description": "Alerte de sécurité — connexion échouée",
            "rule_level": 5,
            "agent_name": "serveur-français",
            "category": "authentication",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)
        assert "serveur-français" in result

    def test_numeric_rule_id_as_string(self):
        """Rule ID should work as string."""
        alert = {
            "rule_id": "00001",
            "rule_description": "Test",
            "rule_level": 3,
            "agent_name": "srv",
            "category": "general",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert "00001" in result


# ─── Anonymisation stress ────────────────────────────────────────────────────

class TestAnonymisationStress:
    """Stress tests for anonymisation."""

    def test_anonymise_10000_records(self):
        """Anonymisation should handle 10000 records."""
        records = [
            {
                "org_id": f"org-{i}",
                "id": str(uuid.uuid4()),
                "name": f"Org {i}",
                "slug": f"org-{i}",
                "domain": f"org{i}.com",
                "vulnerability_count": i,
                "culture_score": float(i % 100),
            }
            for i in range(10000)
        ]
        result = anonymise_records(records)
        assert len(result) == 10000
        for r in result:
            assert "org_id" not in r
            assert "id" not in r
            assert "name" not in r
            assert "vulnerability_count" in r


# ─── Comparison report boundary cases ────────────────────────────────────────

class TestComparisonReportBoundary:
    """Boundary tests for comparison reports."""

    def test_all_50th_percentile(self):
        """All metrics at 50th percentile = average performance."""
        metrics = [
            {"metric": m, "percentile": 50.0, "value": 50.0}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(metrics, {})
        assert "summary" in report

    def test_zero_percentile_metrics(self):
        """Zero percentile should still generate valid report."""
        metrics = [
            {"metric": m, "percentile": 0.0, "value": 0.0}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(metrics, {})
        assert len(report["weaknesses"]) >= 1

    def test_hundred_percentile_metrics(self):
        """100th percentile should still generate valid report."""
        metrics = [
            {"metric": m, "percentile": 100.0, "value": 100.0}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(metrics, {})
        assert len(report["strengths"]) >= 1
