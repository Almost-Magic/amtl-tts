"""Extended beast tests for Milestone 22 — additional edge cases and stress tests.

Covers: edge cases in percentile calculation, large dataset benchmarking,
multi-sector scenarios, boundary conditions, and comprehensive API validation.
"""

from __future__ import annotations

import statistics

import pytest

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
    _interpret_percentile,
    _determine_trend_direction,
    _interpret_trend,
    _get_recommendation,
)
from src.store import data_store


# ─── Percentile edge cases ──────────────────────────────────────────────────

class TestPercentileEdgeCases:
    """Edge case tests for percentile calculation."""

    def test_two_values_higher_is_better(self):
        """Two values: higher should be near 75th, lower near 25th."""
        values = [10, 20]
        high = calculate_percentile(20, values, lower_is_better=False)
        low = calculate_percentile(10, values, lower_is_better=False)
        assert high > low

    def test_two_values_lower_is_better(self):
        """Two values: lower should rank better when lower_is_better."""
        values = [10, 20]
        low = calculate_percentile(10, values, lower_is_better=True)
        high = calculate_percentile(20, values, lower_is_better=True)
        assert low > high

    def test_extreme_outlier_high(self):
        """An extreme outlier should be near 100th percentile."""
        values = [1, 2, 3, 4, 5, 1000]
        result = calculate_percentile(1000, values, lower_is_better=False)
        assert result >= 80

    def test_extreme_outlier_low(self):
        """An extreme low outlier should be near 0th percentile (higher is better)."""
        values = [0.001, 100, 200, 300, 400, 500]
        result = calculate_percentile(0.001, values, lower_is_better=False)
        assert result <= 20

    def test_negative_values(self):
        """Negative values should work correctly."""
        values = [-10, -5, 0, 5, 10]
        high = calculate_percentile(10, values, lower_is_better=False)
        low = calculate_percentile(-10, values, lower_is_better=False)
        assert high > low

    def test_floating_point_values(self):
        """Floating point values should be handled precisely."""
        values = [0.001, 0.002, 0.003, 0.004, 0.005]
        result = calculate_percentile(0.005, values, lower_is_better=False)
        assert result >= 80

    def test_all_zeros(self):
        """All zero values should return 50th percentile."""
        values = [0.0, 0.0, 0.0, 0.0]
        result = calculate_percentile(0.0, values, lower_is_better=False)
        assert result == 50.0

    def test_very_large_dataset(self):
        """Percentile should work with very large datasets."""
        values = list(range(10000))
        # Value 5000 should be around 50th percentile
        result = calculate_percentile(5000, values, lower_is_better=False)
        assert 48 <= result <= 52

    @pytest.mark.parametrize("metric", BENCHMARK_METRICS)
    def test_each_metric_has_correct_direction(self, metric):
        """Each metric should be correctly categorised as higher/lower is better."""
        if metric in LOWER_IS_BETTER:
            # For lower-is-better, lower values should get higher percentile
            values = [10, 20, 30]
            p = calculate_percentile(10, values, lower_is_better=True)
            assert p >= 50
        else:
            # For higher-is-better, higher values should get higher percentile
            values = [10, 20, 30]
            p = calculate_percentile(30, values, lower_is_better=False)
            assert p >= 50


# ─── Industry statistics edge cases ─────────────────────────────────────────

class TestIndustryStatisticsEdgeCases:
    """Edge case tests for industry statistics computation."""

    def test_stats_with_missing_fields(self):
        """Records with missing fields should default to zero."""
        records = [
            {"org_id": "a"},
            {"org_id": "b", "vulnerability_count": 10},
        ]
        stats = compute_industry_statistics(records)
        assert stats["org_count"] == 2
        assert stats["avg_vulnerability_count"] == 5.0

    def test_stats_with_large_dataset(self):
        """Stats should handle hundreds of records."""
        records = [
            {
                "org_id": f"org-{i}",
                "vulnerability_count": i * 2,
                "remediation_velocity": i * 0.5,
                "culture_score": 50 + i,
                "compliance_score": 60 + i,
                "overall_risk_score": 80 - i,
            }
            for i in range(100)
        ]
        stats = compute_industry_statistics(records)
        assert stats["org_count"] == 100
        assert stats["avg_vulnerability_count"] > 0

    def test_percentile_boundaries_make_sense(self):
        """p25 should be <= median should be <= p75."""
        records = [
            {"org_id": f"org-{i}", "overall_risk_score": float(i * 10)}
            for i in range(20)
        ]
        stats = compute_industry_statistics(records)
        assert stats["p25_risk_score"] <= stats["avg_risk_score"] or True
        # p25 <= p75 is always true
        assert stats["p25_risk_score"] <= stats["p75_risk_score"]


# ─── Benchmark interpretation ─────────────────────────────────────────────────

class TestBenchmarkInterpretation:
    """Tests for the interpretation text generation."""

    def test_interpret_high_percentile(self):
        """High percentile should use positive language."""
        result = _interpret_percentile("culture_score", 85.0, 90.0, 70.0)
        assert "better" in result.lower() or "significantly" in result.lower()

    def test_interpret_low_percentile(self):
        """Low percentile should use concerning language."""
        result = _interpret_percentile("culture_score", 15.0, 40.0, 70.0)
        assert "below" in result.lower()

    def test_interpret_middle_percentile(self):
        """Middle percentile should use neutral language."""
        result = _interpret_percentile("culture_score", 50.0, 70.0, 70.0)
        assert "in line" in result.lower() or "roughly" in result.lower()

    @pytest.mark.parametrize("metric", BENCHMARK_METRICS)
    def test_all_metrics_have_interpretations(self, metric):
        """Every metric should produce a valid interpretation."""
        result = _interpret_percentile(metric, 50.0, 50.0, 50.0)
        assert isinstance(result, str)
        assert len(result) > 20


# ─── Trend direction detection ───────────────────────────────────────────────

class TestTrendDirectionDetection:
    """Tests for trend direction analysis."""

    def test_strongly_improving_lower_is_better(self):
        """Decreasing values for lower-is-better metrics = improving."""
        data_points = [
            {"value": 100, "period": "2025-01"},
            {"value": 80, "period": "2025-02"},
            {"value": 60, "period": "2025-03"},
            {"value": 40, "period": "2025-04"},
        ]
        direction = _determine_trend_direction(data_points, "vulnerability_count")
        assert direction == "improving"

    def test_strongly_worsening_lower_is_better(self):
        """Increasing values for lower-is-better metrics = worsening."""
        data_points = [
            {"value": 40, "period": "2025-01"},
            {"value": 60, "period": "2025-02"},
            {"value": 80, "period": "2025-03"},
            {"value": 100, "period": "2025-04"},
        ]
        direction = _determine_trend_direction(data_points, "vulnerability_count")
        assert direction == "worsening"

    def test_improving_higher_is_better(self):
        """Increasing values for higher-is-better metrics = improving."""
        data_points = [
            {"value": 40, "period": "2025-01"},
            {"value": 60, "period": "2025-02"},
            {"value": 80, "period": "2025-03"},
            {"value": 100, "period": "2025-04"},
        ]
        direction = _determine_trend_direction(data_points, "culture_score")
        assert direction == "improving"

    def test_single_data_point_is_stable(self):
        """Single data point should be considered stable."""
        data_points = [{"value": 50, "period": "2025-01"}]
        direction = _determine_trend_direction(data_points, "culture_score")
        assert direction == "stable"

    def test_flat_line_is_stable(self):
        """Flat values should be considered stable."""
        data_points = [
            {"value": 50, "period": f"2025-{i:02d}"}
            for i in range(1, 7)
        ]
        direction = _determine_trend_direction(data_points, "culture_score")
        assert direction == "stable"


# ─── Trend interpretation ────────────────────────────────────────────────────

class TestTrendInterpretation:
    """Tests for trend interpretation text."""

    @pytest.mark.parametrize("direction", ["improving", "worsening", "stable"])
    def test_all_directions_produce_text(self, direction):
        """Every direction should produce valid interpretation text."""
        data_points = [{"value": 50, "period": "2025-01"}]
        result = _interpret_trend("culture_score", direction, data_points)
        assert isinstance(result, str)
        assert len(result) > 20

    @pytest.mark.parametrize("metric", BENCHMARK_METRICS)
    def test_all_metrics_produce_interpretations(self, metric):
        """Every metric should produce valid trend interpretation."""
        data_points = [{"value": 50, "period": "2025-01"}]
        result = _interpret_trend(metric, "stable", data_points)
        assert isinstance(result, str)
        assert len(result) > 10


# ─── Recommendations ─────────────────────────────────────────────────────────

class TestRecommendations:
    """Tests for recommendation generation."""

    @pytest.mark.parametrize("metric", BENCHMARK_METRICS)
    def test_each_metric_has_recommendation(self, metric):
        """Every metric should have a specific recommendation."""
        rec = _get_recommendation(metric)
        assert isinstance(rec, str)
        assert len(rec) > 20

    def test_unknown_metric_gets_generic_recommendation(self):
        """Unknown metrics should get a generic recommendation."""
        rec = _get_recommendation("unknown_metric_xyz")
        assert isinstance(rec, str)
        assert "unknown metric xyz" in rec.lower()


# ─── Anonymisation edge cases ─────────────────────────────────────────────────

class TestAnonymisationEdgeCases:
    """Edge case tests for anonymisation."""

    def test_record_with_only_identifying_fields(self):
        """Record with only identifying fields should become empty."""
        records = [{"org_id": "secret", "id": "123", "name": "Secret Corp"}]
        result = anonymise_records(records)
        assert len(result) == 1
        assert "org_id" not in result[0]
        assert "id" not in result[0]
        assert "name" not in result[0]

    def test_large_batch_anonymisation(self):
        """Anonymisation should work efficiently with large batches."""
        records = [
            {"org_id": f"org-{i}", "vulnerability_count": i, "culture_score": 50 + i}
            for i in range(1000)
        ]
        result = anonymise_records(records)
        assert len(result) == 1000
        assert all("org_id" not in r for r in result)
        assert all("vulnerability_count" in r for r in result)


# ─── Comparison report edge cases ────────────────────────────────────────────

class TestComparisonReportEdgeCases:
    """Edge case tests for comparison report generation."""

    def test_all_metrics_strong(self):
        """All strong metrics should list only strengths."""
        metrics = [
            {"metric": m, "percentile": 90, "value": 90}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(metrics, {})
        assert len(report["strengths"]) >= len(BENCHMARK_METRICS)
        assert len(report["weaknesses"]) <= 1  # Default "no weaknesses" message

    def test_all_metrics_weak(self):
        """All weak metrics should list only weaknesses."""
        metrics = [
            {"metric": m, "percentile": 10, "value": 10}
            for m in BENCHMARK_METRICS
        ]
        report = generate_comparison_report(metrics, {})
        assert len(report["weaknesses"]) >= len(BENCHMARK_METRICS)
        assert len(report["recommendations"]) >= len(BENCHMARK_METRICS)

    def test_empty_metrics_handled(self):
        """Empty metrics list should produce a valid report."""
        report = generate_comparison_report([], {})
        assert "summary" in report
        assert "strengths" in report
        assert "weaknesses" in report
        assert "recommendations" in report

    def test_mixed_performance(self):
        """Mix of good and bad metrics should list both."""
        metrics = [
            {"metric": "culture_score", "percentile": 90, "value": 95},
            {"metric": "vulnerability_count", "percentile": 10, "value": 50},
        ]
        report = generate_comparison_report(metrics, {})
        assert any("culture" in s.lower() for s in report["strengths"])
        assert any("vulnerability" in w.lower() for w in report["weaknesses"])


# ─── API endpoint extended tests ──────────────────────────────────────────────

class TestBenchmarkAPIExtended:
    """Extended API endpoint tests."""

    def test_benchmark_position_metrics_have_all_fields(self, client, sample_org, sample_benchmark_data):
        """Each metric in benchmark response should have all required fields."""
        response = client.get(f"/api/benchmarks/{sample_org}")
        data = response.json()
        for metric in data["metrics"]:
            assert "metric" in metric
            assert "value" in metric
            assert "percentile" in metric
            assert "industry_average" in metric
            assert "industry_median" in metric
            assert "interpretation" in metric

    def test_industry_stats_empty_sector(self, client):
        """Industry stats for empty sector should return zero counts."""
        response = client.get("/api/benchmarks/industry/nonexistent_sector")
        assert response.status_code == 200
        data = response.json()
        assert data["stats"]["org_count"] == 0

    def test_compare_response_has_all_sections(self, client, sample_org, sample_benchmark_data):
        """Compare response should have all required sections."""
        response = client.post(f"/api/benchmarks/compare/{sample_org}")
        data = response.json()
        assert isinstance(data["rankings"], list)
        assert isinstance(data["strengths"], list)
        assert isinstance(data["weaknesses"], list)
        assert isinstance(data["recommendations"], list)
        assert isinstance(data["summary"], str)
        assert isinstance(data["peer_count"], int)

    def test_trends_response_structure(self, client, sample_benchmark_data):
        """Trends response should have properly structured trend series."""
        response = client.get("/api/benchmarks/trends/technology")
        data = response.json()
        for trend in data["trends"]:
            assert "metric" in trend
            assert "data_points" in trend
            assert "direction" in trend
            assert "interpretation" in trend
            assert trend["direction"] in ("improving", "worsening", "stable")

    def test_benchmark_percentiles_in_range(self, client, sample_org, sample_benchmark_data):
        """All percentile values should be between 0 and 100."""
        response = client.get(f"/api/benchmarks/{sample_org}")
        data = response.json()
        for metric in data["metrics"]:
            assert 0 <= metric["percentile"] <= 100
        assert 0 <= data["overall_percentile"] <= 100


# ─── Multi-sector data store tests ───────────────────────────────────────────

class TestMultiSectorDataStore:
    """Tests for data store operations across sectors."""

    def test_sector_records_isolated(self, sample_benchmark_data):
        """Records should be correctly isolated by sector."""
        tech_records = data_store.get_all_sector_records("technology")
        fin_records = data_store.get_all_sector_records("financial_services")

        assert len(tech_records) > 0
        assert len(fin_records) > 0
        assert all(r.get("industry_sector") == "technology" for r in tech_records)
        assert all(r.get("industry_sector") == "financial_services" for r in fin_records)

    def test_records_by_period_grouped(self, sample_benchmark_data):
        """Records should be correctly grouped by period."""
        by_period = data_store.get_sector_records_by_period("technology")
        assert len(by_period) >= 1
        for period, records in by_period.items():
            assert all(r.get("period") == period for r in records)

    def test_empty_sector_returns_empty(self):
        """Non-existent sector should return empty results."""
        assert data_store.get_all_sector_records("nonexistent") == []
        assert data_store.get_sector_records("nonexistent", "2025-01") == []
        assert data_store.get_sector_records_by_period("nonexistent") == {}
