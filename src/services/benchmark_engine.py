"""Industry Benchmark Engine — anonymous comparative analytics."""

from __future__ import annotations

import statistics
from typing import Any


# Supported industry sectors
INDUSTRY_SECTORS = [
    "financial_services",
    "healthcare",
    "technology",
    "retail",
    "manufacturing",
    "education",
    "government",
    "energy",
    "telecommunications",
    "professional_services",
    "general",
]

# Metric definitions
BENCHMARK_METRICS = [
    "vulnerability_count",
    "critical_count",
    "high_count",
    "remediation_velocity",
    "culture_score",
    "compliance_score",
    "overall_risk_score",
]

# Metrics where lower is better
LOWER_IS_BETTER = {
    "vulnerability_count",
    "critical_count",
    "high_count",
    "overall_risk_score",
}


def calculate_percentile(value: float, all_values: list[float], lower_is_better: bool = False) -> float:
    """Calculate the percentile ranking of a value within a distribution.

    For 'lower is better' metrics, a low value gets a high percentile.
    For 'higher is better' metrics, a high value gets a high percentile.

    Args:
        value: The value to rank.
        all_values: All values in the distribution (including the target).
        lower_is_better: If True, lower values rank higher.

    Returns:
        Percentile as a float between 0.0 and 100.0.
    """
    if not all_values:
        return 50.0

    if len(all_values) == 1:
        return 50.0

    sorted_values = sorted(all_values)
    n = len(sorted_values)

    # Count values below this one
    below = sum(1 for v in sorted_values if v < value)
    equal = sum(1 for v in sorted_values if v == value)

    # Percentile rank using midpoint method
    percentile = ((below + 0.5 * equal) / n) * 100

    if lower_is_better:
        # Invert: lower value = higher percentile
        percentile = 100 - percentile

    return round(percentile, 1)


def compute_industry_statistics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregated statistics for an industry sector.

    Takes a list of benchmark records and calculates averages, medians,
    and percentile boundaries.

    Args:
        records: List of benchmark record dicts with metric values.

    Returns:
        Dict with aggregated statistics.
    """
    if not records:
        return {
            "org_count": 0,
            "avg_vulnerability_count": 0.0,
            "avg_remediation_velocity": 0.0,
            "avg_culture_score": 0.0,
            "avg_compliance_score": 0.0,
            "avg_risk_score": 0.0,
            "median_vulnerability_count": 0.0,
            "p25_risk_score": 0.0,
            "p75_risk_score": 0.0,
        }

    def _avg(key: str) -> float:
        vals = [r.get(key, 0) for r in records]
        return round(statistics.mean(vals), 2) if vals else 0.0

    def _median(key: str) -> float:
        vals = [r.get(key, 0) for r in records]
        return round(statistics.median(vals), 2) if vals else 0.0

    def _percentile(key: str, p: float) -> float:
        vals = sorted(r.get(key, 0) for r in records)
        if not vals:
            return 0.0
        k = (len(vals) - 1) * (p / 100)
        f = int(k)
        c = f + 1
        if c >= len(vals):
            return round(vals[f], 2)
        return round(vals[f] + (k - f) * (vals[c] - vals[f]), 2)

    return {
        "org_count": len(set(r.get("org_id", "") for r in records)),
        "avg_vulnerability_count": _avg("vulnerability_count"),
        "avg_remediation_velocity": _avg("remediation_velocity"),
        "avg_culture_score": _avg("culture_score"),
        "avg_compliance_score": _avg("compliance_score"),
        "avg_risk_score": _avg("overall_risk_score"),
        "median_vulnerability_count": _median("vulnerability_count"),
        "p25_risk_score": _percentile("overall_risk_score", 25),
        "p75_risk_score": _percentile("overall_risk_score", 75),
    }


def compute_org_benchmark(
    org_record: dict[str, Any],
    all_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compute an organisation's benchmark position across all metrics.

    Args:
        org_record: The target org's benchmark record.
        all_records: All records in the same industry/period (including the org's).

    Returns:
        List of MetricPercentile-like dicts.
    """
    metrics = []
    for metric in BENCHMARK_METRICS:
        org_value = org_record.get(metric, 0)
        all_values = [r.get(metric, 0) for r in all_records]
        lower_better = metric in LOWER_IS_BETTER

        percentile = calculate_percentile(org_value, all_values, lower_is_better=lower_better)
        avg = statistics.mean(all_values) if all_values else 0.0
        med = statistics.median(all_values) if all_values else 0.0

        interpretation = _interpret_percentile(metric, percentile, org_value, avg)

        metrics.append({
            "metric": metric,
            "value": org_value,
            "percentile": percentile,
            "industry_average": round(avg, 2),
            "industry_median": round(med, 2),
            "interpretation": interpretation,
        })

    return metrics


def _interpret_percentile(metric: str, percentile: float, value: float, average: float) -> str:
    """Generate a plain English interpretation of a metric's percentile."""
    metric_labels = {
        "vulnerability_count": "vulnerability count",
        "critical_count": "critical vulnerability count",
        "high_count": "high-severity vulnerability count",
        "remediation_velocity": "remediation speed",
        "culture_score": "security culture score",
        "compliance_score": "compliance score",
        "overall_risk_score": "overall risk score",
    }
    label = metric_labels.get(metric, metric)

    if percentile >= 80:
        position = "significantly better than"
    elif percentile >= 60:
        position = "better than"
    elif percentile >= 40:
        position = "roughly in line with"
    elif percentile >= 20:
        position = "below"
    else:
        position = "significantly below"

    return (
        f"Your {label} ({value}) is {position} the industry average ({round(average, 1)}), "
        f"placing you in the {percentile}th percentile."
    )


def compute_trend_data(
    records_by_period: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Compute trend data across multiple periods.

    Args:
        records_by_period: Dict mapping period strings (YYYY-MM) to lists of records.

    Returns:
        List of trend series dicts, one per metric.
    """
    sorted_periods = sorted(records_by_period.keys())
    trends = []

    for metric in BENCHMARK_METRICS:
        data_points = []
        prev_value = None

        for period in sorted_periods:
            records = records_by_period[period]
            values = [r.get(metric, 0) for r in records]
            avg_value = statistics.mean(values) if values else 0.0

            change_pct = None
            if prev_value is not None and prev_value != 0:
                change_pct = round(((avg_value - prev_value) / abs(prev_value)) * 100, 1)

            data_points.append({
                "period": period,
                "value": round(avg_value, 2),
                "change_pct": change_pct,
            })
            prev_value = avg_value

        direction = _determine_trend_direction(data_points, metric)
        interpretation = _interpret_trend(metric, direction, data_points)

        trends.append({
            "metric": metric,
            "data_points": data_points,
            "direction": direction,
            "interpretation": interpretation,
        })

    return trends


def _determine_trend_direction(
    data_points: list[dict[str, Any]], metric: str
) -> str:
    """Determine the overall direction of a trend series."""
    if len(data_points) < 2:
        return "stable"

    values = [dp["value"] for dp in data_points]
    first_half = statistics.mean(values[: len(values) // 2]) if values[: len(values) // 2] else 0
    second_half = statistics.mean(values[len(values) // 2 :]) if values[len(values) // 2 :] else 0

    if first_half == 0 and second_half == 0:
        return "stable"

    change = (second_half - first_half) / max(abs(first_half), 0.001) * 100

    lower_better = metric in LOWER_IS_BETTER

    if abs(change) < 5:
        return "stable"
    if change > 0:
        return "worsening" if lower_better else "improving"
    return "improving" if lower_better else "worsening"


def _interpret_trend(
    metric: str, direction: str, data_points: list[dict[str, Any]]
) -> str:
    """Generate a plain English interpretation of a trend."""
    metric_labels = {
        "vulnerability_count": "Average vulnerability count",
        "critical_count": "Average critical vulnerability count",
        "high_count": "Average high-severity vulnerability count",
        "remediation_velocity": "Remediation speed",
        "culture_score": "Security culture scores",
        "compliance_score": "Compliance scores",
        "overall_risk_score": "Overall risk scores",
    }
    label = metric_labels.get(metric, metric)
    n_periods = len(data_points)

    direction_text = {
        "improving": "been improving",
        "worsening": "been worsening",
        "stable": "remained relatively stable",
    }

    return (
        f"{label} across the industry has {direction_text.get(direction, 'remained stable')} "
        f"over the past {n_periods} period(s)."
    )


def anonymise_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove identifying information from benchmark records.

    Strips org_id and any other potentially identifying fields,
    keeping only the metric values for comparative analysis.
    """
    anonymised = []
    for record in records:
        clean = {
            k: v
            for k, v in record.items()
            if k not in ("org_id", "id", "created_at", "updated_at", "name", "slug", "domain")
        }
        anonymised.append(clean)
    return anonymised


def generate_comparison_report(
    org_metrics: list[dict[str, Any]],
    org_record: dict[str, Any],
) -> dict[str, Any]:
    """Generate a comparative analysis report with strengths, weaknesses, recommendations.

    Args:
        org_metrics: List of MetricPercentile-like dicts from compute_org_benchmark.
        org_record: The org's benchmark record.

    Returns:
        Dict with strengths, weaknesses, and recommendations.
    """
    strengths = []
    weaknesses = []
    recommendations = []

    for m in org_metrics:
        metric = m["metric"]
        percentile = m["percentile"]
        label = metric.replace("_", " ")

        if percentile >= 70:
            strengths.append(f"Strong {label} — {percentile}th percentile")
        elif percentile <= 30:
            weaknesses.append(f"Below-average {label} — {percentile}th percentile")
            recommendations.append(_get_recommendation(metric))

    if not strengths:
        strengths.append("No metrics significantly above industry average")
    if not weaknesses:
        weaknesses.append("No metrics significantly below industry average")
    if not recommendations:
        recommendations.append("Continue maintaining current security posture")

    overall_percentile = statistics.mean([m["percentile"] for m in org_metrics]) if org_metrics else 50.0

    summary = (
        f"Overall, the organisation sits at approximately the {round(overall_percentile)}th "
        f"percentile in its industry sector, with {len(strengths)} notable strength(s) "
        f"and {len(weaknesses)} area(s) for improvement."
    )

    return {
        "strengths": strengths,
        "weaknesses": weaknesses,
        "recommendations": recommendations,
        "summary": summary,
    }


def _get_recommendation(metric: str) -> str:
    """Return a recommendation for a below-average metric."""
    recs = {
        "vulnerability_count": (
            "Prioritise vulnerability remediation — consider automated patching "
            "and more frequent scanning cycles."
        ),
        "critical_count": (
            "Critical vulnerabilities require urgent attention — establish a "
            "48-hour SLA for critical findings."
        ),
        "high_count": (
            "High-severity vulnerabilities should be addressed within 7 days — "
            "review prioritisation processes."
        ),
        "remediation_velocity": (
            "Remediation velocity is below average — consider dedicated "
            "security sprint cycles and automated remediation workflows."
        ),
        "culture_score": (
            "Security culture could be strengthened — invest in awareness "
            "training and embed security champions in development teams."
        ),
        "compliance_score": (
            "Compliance gaps detected — conduct a thorough gap analysis "
            "against relevant frameworks and create a remediation roadmap."
        ),
        "overall_risk_score": (
            "Overall risk posture needs improvement — consider a comprehensive "
            "security programme review with executive sponsorship."
        ),
    }
    return recs.get(metric, f"Review and improve {metric.replace('_', ' ')}.")
