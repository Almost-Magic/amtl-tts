"""Industry Benchmark Engine API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.schemas.benchmark import (
    BenchmarkPosition,
    CompareRequest,
    CompareResponse,
    IndustryStatsResponse,
    MetricPercentile,
    TrendResponse,
    TrendSeries,
    TrendPoint,
    IndustryStat,
)
from src.services.benchmark_engine import (
    anonymise_records,
    compute_industry_statistics,
    compute_org_benchmark,
    compute_trend_data,
    generate_comparison_report,
)
from src.store import data_store

router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])


@router.get("/{org}", response_model=BenchmarkPosition)
async def get_benchmark_position(org: str) -> BenchmarkPosition:
    """Get an organisation's benchmark position within its industry sector."""
    if org not in data_store.organisations:
        raise HTTPException(status_code=404, detail=f"Organisation '{org}' not found")

    org_data = data_store.organisations[org]
    sector = org_data.get("industry_sector", "general")

    # Get the org's latest benchmark record
    org_records = data_store.get_benchmark_records(org)
    if not org_records:
        raise HTTPException(
            status_code=404,
            detail=f"No benchmark data available for '{org}'",
        )

    org_record = org_records[-1]  # Latest record
    period = org_record.get("period", "unknown")

    # Get all records for the same sector and period
    sector_records = data_store.get_sector_records(sector, period)

    # Compute benchmark position
    metrics = compute_org_benchmark(org_record, sector_records)

    import statistics as stats
    overall_percentile = stats.mean([m["percentile"] for m in metrics]) if metrics else 50.0

    metric_responses = [
        MetricPercentile(
            metric=m["metric"],
            value=m["value"],
            percentile=m["percentile"],
            industry_average=m["industry_average"],
            industry_median=m["industry_median"],
            interpretation=m["interpretation"],
        )
        for m in metrics
    ]

    peer_count = len(set(r.get("org_id", "") for r in sector_records))

    summary = (
        f"In the {sector.replace('_', ' ')} sector for period {period}, "
        f"this organisation sits at the {round(overall_percentile)}th percentile overall "
        f"across {peer_count} peer organisation(s)."
    )

    return BenchmarkPosition(
        org_id=org,
        industry_sector=sector,
        period=period,
        overall_percentile=round(overall_percentile, 1),
        metrics=metric_responses,
        peer_count=peer_count,
        summary=summary,
    )


@router.get("/industry/{sector}", response_model=IndustryStatsResponse)
async def get_industry_stats(sector: str) -> IndustryStatsResponse:
    """Get aggregated statistics for an industry sector."""
    # Get current period
    from datetime import datetime, timezone
    current_period = datetime.now(timezone.utc).strftime("%Y-%m")

    # Get all records for this sector
    sector_records = data_store.get_sector_records(sector, current_period)
    if not sector_records:
        # Try any period
        sector_records = data_store.get_all_sector_records(sector)
        if sector_records:
            current_period = sector_records[-1].get("period", current_period)

    # Anonymise before computing
    anonymised = anonymise_records(sector_records)
    stats = compute_industry_statistics(sector_records)

    industry_stat = IndustryStat(
        industry_sector=sector,
        period=current_period,
        org_count=stats["org_count"],
        avg_vulnerability_count=stats["avg_vulnerability_count"],
        avg_remediation_velocity=stats["avg_remediation_velocity"],
        avg_culture_score=stats["avg_culture_score"],
        avg_compliance_score=stats["avg_compliance_score"],
        avg_risk_score=stats["avg_risk_score"],
        median_vulnerability_count=stats["median_vulnerability_count"],
        p25_risk_score=stats["p25_risk_score"],
        p75_risk_score=stats["p75_risk_score"],
    )

    org_count = stats["org_count"]
    summary = (
        f"Industry statistics for {sector.replace('_', ' ')} based on {org_count} "
        f"organisation(s). Average risk score: {stats['avg_risk_score']}, "
        f"average vulnerability count: {stats['avg_vulnerability_count']}."
    )

    return IndustryStatsResponse(
        industry_sector=sector,
        current_period=current_period,
        stats=industry_stat,
        summary=summary,
    )


@router.get("/trends/{sector}", response_model=TrendResponse)
async def get_industry_trends(sector: str) -> TrendResponse:
    """Get industry trend data over time."""
    records_by_period = data_store.get_sector_records_by_period(sector)

    if not records_by_period:
        return TrendResponse(
            industry_sector=sector,
            periods_covered=0,
            trends=[],
            summary=f"No trend data available for {sector.replace('_', ' ')}.",
        )

    trend_data = compute_trend_data(records_by_period)

    trend_series = [
        TrendSeries(
            metric=t["metric"],
            data_points=[
                TrendPoint(
                    period=dp["period"],
                    value=dp["value"],
                    change_pct=dp.get("change_pct"),
                )
                for dp in t["data_points"]
            ],
            direction=t["direction"],
            interpretation=t["interpretation"],
        )
        for t in trend_data
    ]

    periods_covered = len(records_by_period)
    improving = sum(1 for t in trend_data if t["direction"] == "improving")
    worsening = sum(1 for t in trend_data if t["direction"] == "worsening")

    summary = (
        f"Trend analysis for {sector.replace('_', ' ')} across {periods_covered} period(s). "
        f"{improving} metric(s) improving, {worsening} metric(s) worsening."
    )

    return TrendResponse(
        industry_sector=sector,
        periods_covered=periods_covered,
        trends=trend_series,
        summary=summary,
    )


@router.post("/compare/{org}", response_model=CompareResponse)
async def compare_organisation(
    org: str,
    request: CompareRequest | None = None,
) -> CompareResponse:
    """Run comparative analysis for an organisation against its peers."""
    if request is None:
        request = CompareRequest()

    if org not in data_store.organisations:
        raise HTTPException(status_code=404, detail=f"Organisation '{org}' not found")

    org_data = data_store.organisations[org]
    sector = org_data.get("industry_sector", "general")

    # Get org's latest benchmark record
    org_records = data_store.get_benchmark_records(org)
    if not org_records:
        raise HTTPException(
            status_code=404,
            detail=f"No benchmark data available for '{org}'",
        )

    org_record = org_records[-1]
    period = org_record.get("period", "unknown")

    # Get sector records
    sector_records = data_store.get_sector_records(sector, period)

    # Compute metrics
    metrics = compute_org_benchmark(org_record, sector_records)

    # Generate comparison report
    report = generate_comparison_report(metrics, org_record)

    metric_responses = [
        MetricPercentile(
            metric=m["metric"],
            value=m["value"],
            percentile=m["percentile"],
            industry_average=m["industry_average"],
            industry_median=m["industry_median"],
            interpretation=m["interpretation"],
        )
        for m in metrics
    ]

    peer_count = len(set(r.get("org_id", "") for r in sector_records))

    return CompareResponse(
        org_id=org,
        industry_sector=sector,
        period=period,
        rankings=metric_responses,
        strengths=report["strengths"],
        weaknesses=report["weaknesses"],
        recommendations=report["recommendations"],
        peer_count=peer_count,
        summary=report["summary"],
    )
