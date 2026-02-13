"""Beast tests for Milestone 22 — Industry Benchmark Engine.

Tests cover: percentile calculation, anonymisation, trend tracking,
industry statistics, comparative analysis, and API endpoints.
"""

from __future__ import annotations

import statistics

import pytest
from fastapi.testclient import TestClient

from src.services.benchmark_engine import (
    BENCHMARK_METRICS,
    INDUSTRY_SECTORS,
    LOWER_IS_BETTER,
    anonymise_records,
    calculate_percentile,
    compute_industry_statistics,
    compute_org_benchmark,
    compute_trend_data,
    generate_comparison_report,
)
from src.store import data_store


# ─── Test 1: Percentile calculation ──────────────────────────────────────────

class TestPercentileCalculation:
    """Tests for the percentile ranking function."""

    def test_highest_value_gets_high_percentile(self):
        """The highest value should be near the 100th percentile (higher is better)."""
        values = [10, 20, 30, 40, 50]
        result = calculate_percentile(50, values, lower_is_better=False)
        assert result >= 80

    def test_lowest_value_gets_low_percentile(self):
        """The lowest value should be near the 0th percentile (higher is better)."""
        values = [10, 20, 30, 40, 50]
        result = calculate_percentile(10, values, lower_is_better=False)
        assert result <= 20

    def test_lower_is_better_inverts_ranking(self):
        """For 'lower is better' metrics, low values should rank high."""
        values = [10, 20, 30, 40, 50]
        result = calculate_percentile(10, values, lower_is_better=True)
        assert result >= 80

    def test_higher_is_better_normal_ranking(self):
        """For 'higher is better' metrics, high values should rank high."""
        values = [10, 20, 30, 40, 50]
        result_high = calculate_percentile(50, values, lower_is_better=False)
        result_low = calculate_percentile(10, values, lower_is_better=False)
        assert result_high > result_low

    def test_single_value_returns_fifty(self):
        """Single-element distribution should return 50th percentile."""
        result = calculate_percentile(42, [42], lower_is_better=False)
        assert result == 50.0

    def test_empty_values_returns_fifty(self):
        """Empty distribution should return 50th percentile."""
        result = calculate_percentile(42, [], lower_is_better=False)
        assert result == 50.0

    def test_percentile_range_valid(self):
        """Percentile should always be between 0 and 100."""
        values = list(range(1, 101))
        for v in values:
            p = calculate_percentile(v, values, lower_is_better=False)
            assert 0.0 <= p <= 100.0

    def test_identical_values_get_same_percentile(self):
        """All identical values should get the same percentile."""
        values = [50, 50, 50, 50, 50]
        results = [calculate_percentile(50, values, lower_is_better=False) for _ in range(3)]
        assert len(set(results)) == 1  # All the same

    def test_large_distribution_accuracy(self):
        """Percentile should be accurate with a large distribution."""
        values = list(range(1, 1001))
        # Value at position 500 should be around 50th percentile
        result = calculate_percentile(500, values, lower_is_better=False)
        assert 45 <= result <= 55

    def test_vulnerability_count_lower_is_better(self):
        """vulnerability_count should use lower-is-better semantics."""
        assert "vulnerability_count" in LOWER_IS_BETTER
        values = [5, 10, 15, 20, 25]
        result = calculate_percentile(5, values, lower_is_better=True)
        assert result >= 70  # Low count = good ranking


# ─── Test 2: Industry statistics computation ────────────────────────────────

class TestIndustryStatistics:
    """Tests for computing aggregated industry statistics."""

    def test_compute_stats_basic(self):
        """Should compute correct averages and medians."""
        records = [
            {"org_id": "a", "vulnerability_count": 10, "remediation_velocity": 3.0,
             "culture_score": 70, "compliance_score": 80, "overall_risk_score": 50},
            {"org_id": "b", "vulnerability_count": 20, "remediation_velocity": 5.0,
             "culture_score": 80, "compliance_score": 90, "overall_risk_score": 40},
        ]
        stats = compute_industry_statistics(records)

        assert stats["org_count"] == 2
        assert stats["avg_vulnerability_count"] == 15.0
        assert stats["avg_remediation_velocity"] == 4.0
        assert stats["avg_culture_score"] == 75.0
        assert stats["avg_compliance_score"] == 85.0

    def test_compute_stats_empty_input(self):
        """Empty input should return zeroed stats."""
        stats = compute_industry_statistics([])
        assert stats["org_count"] == 0
        assert stats["avg_vulnerability_count"] == 0.0

    def test_compute_stats_single_record(self):
        """Single record should have value == average == median."""
        records = [
            {"org_id": "a", "vulnerability_count": 10, "remediation_velocity": 3.0,
             "culture_score": 70, "compliance_score": 80, "overall_risk_score": 50},
        ]
        stats = compute_industry_statistics(records)
        assert stats["avg_vulnerability_count"] == 10.0
        assert stats["median_vulnerability_count"] == 10.0

    def test_compute_stats_percentile_boundaries(self):
        """p25 and p75 should bracket the median."""
        records = [
            {"org_id": f"org-{i}", "overall_risk_score": float(i * 10)}
            for i in range(1, 11)
        ]
        stats = compute_industry_statistics(records)
        assert stats["p25_risk_score"] <= stats["avg_risk_score"]
        assert stats["p75_risk_score"] >= stats["avg_risk_score"]


# ─── Test 3: Organisation benchmark position ────────────────────────────────

class TestOrgBenchmark:
    """Tests for computing an org's benchmark position."""

    def test_benchmark_returns_all_metrics(self):
        """Benchmark should return a result for each defined metric."""
        org_record = {
            "vulnerability_count": 15, "critical_count": 2, "high_count": 5,
            "remediation_velocity": 3.5, "culture_score": 72.0,
            "compliance_score": 80.0, "overall_risk_score": 65.0,
        }
        all_records = [org_record]
        metrics = compute_org_benchmark(org_record, all_records)
        metric_names = {m["metric"] for m in metrics}
        assert metric_names == set(BENCHMARK_METRICS)

    def test_benchmark_top_performer(self):
        """An org with the best scores should have high percentiles."""
        org_record = {
            "vulnerability_count": 2, "critical_count": 0, "high_count": 1,
            "remediation_velocity": 8.0, "culture_score": 95.0,
            "compliance_score": 98.0, "overall_risk_score": 10.0,
        }
        weak_records = [
            {"vulnerability_count": 30, "critical_count": 5, "high_count": 15,
             "remediation_velocity": 1.0, "culture_score": 40.0,
             "compliance_score": 50.0, "overall_risk_score": 90.0},
        ] * 9

        metrics = compute_org_benchmark(org_record, [org_record] + weak_records)
        avg_percentile = statistics.mean([m["percentile"] for m in metrics])
        assert avg_percentile >= 70

    def test_benchmark_bottom_performer(self):
        """An org with the worst scores should have low percentiles."""
        org_record = {
            "vulnerability_count": 50, "critical_count": 10, "high_count": 20,
            "remediation_velocity": 0.5, "culture_score": 20.0,
            "compliance_score": 30.0, "overall_risk_score": 95.0,
        }
        strong_records = [
            {"vulnerability_count": 5, "critical_count": 0, "high_count": 1,
             "remediation_velocity": 8.0, "culture_score": 90.0,
             "compliance_score": 95.0, "overall_risk_score": 15.0},
        ] * 9

        metrics = compute_org_benchmark(org_record, [org_record] + strong_records)
        avg_percentile = statistics.mean([m["percentile"] for m in metrics])
        assert avg_percentile <= 30

    def test_benchmark_includes_interpretations(self):
        """Each metric should have a human-readable interpretation."""
        org_record = {
            "vulnerability_count": 15, "critical_count": 2, "high_count": 5,
            "remediation_velocity": 3.5, "culture_score": 72.0,
            "compliance_score": 80.0, "overall_risk_score": 65.0,
        }
        metrics = compute_org_benchmark(org_record, [org_record])
        for m in metrics:
            assert "interpretation" in m
            assert len(m["interpretation"]) > 20


# ─── Test 4: Anonymisation ───────────────────────────────────────────────────

class TestAnonymisation:
    """Tests for removing identifying information from records."""

    def test_org_id_removed(self):
        """org_id should be stripped from anonymised records."""
        records = [
            {"org_id": "secret-corp", "vulnerability_count": 10, "culture_score": 70},
        ]
        result = anonymise_records(records)
        assert all("org_id" not in r for r in result)

    def test_identifying_fields_removed(self):
        """All potentially identifying fields should be stripped."""
        records = [{
            "org_id": "secret-corp",
            "id": "uuid-123",
            "name": "Secret Corp",
            "slug": "secret-corp",
            "domain": "secret.com",
            "created_at": "2025-01-01",
            "updated_at": "2025-01-02",
            "vulnerability_count": 10,
        }]
        result = anonymise_records(records)
        for r in result:
            assert "org_id" not in r
            assert "id" not in r
            assert "name" not in r
            assert "slug" not in r
            assert "domain" not in r

    def test_metric_values_preserved(self):
        """Metric values should be preserved after anonymisation."""
        records = [
            {"org_id": "test", "vulnerability_count": 42, "culture_score": 85.5},
        ]
        result = anonymise_records(records)
        assert result[0]["vulnerability_count"] == 42
        assert result[0]["culture_score"] == 85.5

    def test_empty_records_anonymised(self):
        """Empty list should return empty list."""
        assert anonymise_records([]) == []


# ─── Test 5: Trend computation ───────────────────────────────────────────────

class TestTrendComputation:
    """Tests for computing industry trends over time."""

    def test_improving_trend_detected(self):
        """Decreasing vulnerability counts should show as 'improving'."""
        records_by_period = {
            "2025-01": [{"vulnerability_count": 30, "overall_risk_score": 80}],
            "2025-02": [{"vulnerability_count": 25, "overall_risk_score": 70}],
            "2025-03": [{"vulnerability_count": 20, "overall_risk_score": 60}],
            "2025-04": [{"vulnerability_count": 15, "overall_risk_score": 50}],
        }
        trends = compute_trend_data(records_by_period)
        vuln_trend = next(t for t in trends if t["metric"] == "vulnerability_count")
        assert vuln_trend["direction"] == "improving"

    def test_worsening_trend_detected(self):
        """Increasing vulnerability counts should show as 'worsening'."""
        records_by_period = {
            "2025-01": [{"vulnerability_count": 10, "overall_risk_score": 30}],
            "2025-02": [{"vulnerability_count": 15, "overall_risk_score": 40}],
            "2025-03": [{"vulnerability_count": 20, "overall_risk_score": 55}],
            "2025-04": [{"vulnerability_count": 30, "overall_risk_score": 70}],
        }
        trends = compute_trend_data(records_by_period)
        vuln_trend = next(t for t in trends if t["metric"] == "vulnerability_count")
        assert vuln_trend["direction"] == "worsening"

    def test_stable_trend_detected(self):
        """Roughly constant values should show as 'stable'."""
        records_by_period = {
            "2025-01": [{"vulnerability_count": 20, "culture_score": 70}],
            "2025-02": [{"vulnerability_count": 20, "culture_score": 70}],
            "2025-03": [{"vulnerability_count": 21, "culture_score": 71}],
            "2025-04": [{"vulnerability_count": 20, "culture_score": 70}],
        }
        trends = compute_trend_data(records_by_period)
        vuln_trend = next(t for t in trends if t["metric"] == "vulnerability_count")
        assert vuln_trend["direction"] == "stable"

    def test_trend_data_points_match_periods(self):
        """Each trend should have the same number of data points as periods."""
        records_by_period = {
            f"2025-{i:02d}": [{"vulnerability_count": 10 + i}]
            for i in range(1, 7)
        }
        trends = compute_trend_data(records_by_period)
        for trend in trends:
            assert len(trend["data_points"]) == 6

    def test_trend_change_pct_calculated(self):
        """Change percentage should be calculated between consecutive periods."""
        records_by_period = {
            "2025-01": [{"vulnerability_count": 100}],
            "2025-02": [{"vulnerability_count": 110}],
        }
        trends = compute_trend_data(records_by_period)
        vuln_trend = next(t for t in trends if t["metric"] == "vulnerability_count")
        # Second point should have change_pct
        assert vuln_trend["data_points"][1]["change_pct"] is not None
        assert vuln_trend["data_points"][1]["change_pct"] == pytest.approx(10.0, abs=0.5)

    def test_trend_interpretations_generated(self):
        """Each trend should have a human-readable interpretation."""
        records_by_period = {
            "2025-01": [{"vulnerability_count": 10}],
            "2025-02": [{"vulnerability_count": 20}],
        }
        trends = compute_trend_data(records_by_period)
        for trend in trends:
            assert "interpretation" in trend
            assert len(trend["interpretation"]) > 10

    def test_empty_periods_handled(self):
        """Empty period data should return empty trends gracefully."""
        trends = compute_trend_data({})
        assert trends == [] or all(len(t["data_points"]) == 0 for t in trends)


# ─── Test 6: Comparison report generation ────────────────────────────────────

class TestComparisonReport:
    """Tests for generating comparison reports."""

    def test_report_identifies_strengths(self):
        """High-percentile metrics should be listed as strengths."""
        org_metrics = [
            {"metric": "culture_score", "percentile": 85, "value": 90},
            {"metric": "vulnerability_count", "percentile": 90, "value": 5},
            {"metric": "compliance_score", "percentile": 25, "value": 50},
        ]
        report = generate_comparison_report(org_metrics, {})
        assert any("culture" in s.lower() for s in report["strengths"])

    def test_report_identifies_weaknesses(self):
        """Low-percentile metrics should be listed as weaknesses."""
        org_metrics = [
            {"metric": "compliance_score", "percentile": 15, "value": 40},
            {"metric": "culture_score", "percentile": 80, "value": 85},
        ]
        report = generate_comparison_report(org_metrics, {})
        assert any("compliance" in w.lower() for w in report["weaknesses"])

    def test_report_includes_recommendations(self):
        """Weaknesses should generate actionable recommendations."""
        org_metrics = [
            {"metric": "remediation_velocity", "percentile": 10, "value": 0.5},
        ]
        report = generate_comparison_report(org_metrics, {})
        assert len(report["recommendations"]) >= 1
        assert any("remediation" in r.lower() for r in report["recommendations"])

    def test_report_summary_generated(self):
        """Report should include a summary paragraph."""
        org_metrics = [
            {"metric": "culture_score", "percentile": 50, "value": 70},
        ]
        report = generate_comparison_report(org_metrics, {})
        assert "summary" in report
        assert len(report["summary"]) > 20

    def test_no_weaknesses_case(self):
        """Org with all good scores should have no weaknesses (or a placeholder)."""
        org_metrics = [
            {"metric": m, "percentile": 85, "value": 90}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(org_metrics, {})
        assert len(report["strengths"]) >= 1


# ─── Test 7: API endpoints ───────────────────────────────────────────────────

class TestBenchmarkAPIEndpoints:
    """Tests for Benchmark Engine API endpoints."""

    def test_get_benchmark_position(self, client, sample_org, sample_benchmark_data):
        """GET /api/benchmarks/{org} should return benchmark position."""
        response = client.get(f"/api/benchmarks/{sample_org}")
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == sample_org
        assert data["industry_sector"] == "technology"
        assert "metrics" in data
        assert len(data["metrics"]) == len(BENCHMARK_METRICS)
        assert "summary" in data
        assert data["peer_count"] >= 1

    def test_get_benchmark_unknown_org_returns_404(self, client):
        """Benchmark for unknown org should return 404."""
        response = client.get("/api/benchmarks/nonexistent")
        assert response.status_code == 404

    def test_get_benchmark_no_data_returns_404(self, client, sample_org):
        """Benchmark for org with no records should return 404."""
        response = client.get(f"/api/benchmarks/{sample_org}")
        assert response.status_code == 404

    def test_get_industry_stats(self, client, sample_benchmark_data):
        """GET /api/benchmarks/industry/{sector} should return stats."""
        response = client.get("/api/benchmarks/industry/technology")
        assert response.status_code == 200
        data = response.json()
        assert data["industry_sector"] == "technology"
        assert "stats" in data
        assert data["stats"]["org_count"] >= 1

    def test_get_industry_trends(self, client, sample_benchmark_data):
        """GET /api/benchmarks/trends/{sector} should return trends."""
        response = client.get("/api/benchmarks/trends/technology")
        assert response.status_code == 200
        data = response.json()
        assert data["industry_sector"] == "technology"
        assert data["periods_covered"] >= 1
        assert isinstance(data["trends"], list)

    def test_get_trends_empty_sector(self, client):
        """Trends for a sector with no data should return empty trends."""
        response = client.get("/api/benchmarks/trends/nonexistent_sector")
        assert response.status_code == 200
        data = response.json()
        assert data["periods_covered"] == 0

    def test_compare_organisation(self, client, sample_org, sample_benchmark_data):
        """POST /api/benchmarks/compare/{org} should return comparison."""
        response = client.post(f"/api/benchmarks/compare/{sample_org}")
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == sample_org
        assert "rankings" in data
        assert "strengths" in data
        assert "weaknesses" in data
        assert "recommendations" in data
        assert "summary" in data

    def test_compare_unknown_org_returns_404(self, client):
        """Compare for unknown org should return 404."""
        response = client.post("/api/benchmarks/compare/nonexistent")
        assert response.status_code == 404


# ─── Test 8: Industry sector configuration ───────────────────────────────────

class TestIndustrySectorConfig:
    """Tests for industry sector configuration."""

    def test_minimum_sectors_defined(self):
        """At least 5 industry sectors should be defined."""
        assert len(INDUSTRY_SECTORS) >= 5

    def test_general_sector_exists(self):
        """A 'general' fallback sector should exist."""
        assert "general" in INDUSTRY_SECTORS

    def test_financial_services_sector_exists(self):
        """Financial services should be a defined sector."""
        assert "financial_services" in INDUSTRY_SECTORS

    def test_technology_sector_exists(self):
        """Technology should be a defined sector."""
        assert "technology" in INDUSTRY_SECTORS
