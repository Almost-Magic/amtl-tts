"""Wazuh Cross-Domain Correlation API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

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
from src.services.wazuh_correlation import (
    build_unified_timeline,
    correlate_alerts_with_vulnerabilities,
    generate_timeline_summary,
    translate_wazuh_alert_to_plain_english,
)
from src.store import data_store

router = APIRouter(prefix="/api/wazuh", tags=["wazuh"])


@router.post("/connect", response_model=WazuhConnectResponse)
async def connect_wazuh(request: WazuhConnectRequest) -> WazuhConnectResponse:
    """Configure a Wazuh SIEM connection for an organisation."""
    connection = {
        "org_id": request.org_id,
        "api_url": request.api_url,
        "api_user": request.api_user,
        "api_password_encrypted": request.api_password,
        "verify_ssl": request.verify_ssl,
        "is_active": True,
    }
    data_store.wazuh_connections[request.org_id] = connection

    return WazuhConnectResponse(
        org_id=request.org_id,
        api_url=request.api_url,
        is_active=True,
        message="Wazuh connection configured successfully.",
    )


@router.post("/correlate/{org}", response_model=CorrelateResult)
async def run_correlation(
    org: str,
    request: CorrelationRequest | None = None,
) -> CorrelateResult:
    """Run cross-domain correlation between Wazuh alerts and Digital Sentinel findings."""
    if request is None:
        request = CorrelationRequest()

    # Validate org exists
    if org not in data_store.organisations:
        raise HTTPException(status_code=404, detail=f"Organisation '{org}' not found")

    # Get Wazuh alerts and vulnerabilities for this org
    wazuh_alerts = data_store.get_wazuh_alerts(org)
    vulnerabilities = data_store.get_vulnerabilities(org)

    # Run correlation engine
    correlations = correlate_alerts_with_vulnerabilities(
        wazuh_alerts=wazuh_alerts,
        vulnerabilities=vulnerabilities,
        min_confidence=request.min_confidence,
    )

    # Store results
    data_store.correlation_results[org] = correlations

    high_severity = sum(1 for c in correlations if c["severity"] in ("critical", "high"))

    correlation_responses = [
        CorrelationResponse(
            id=c["id"],
            correlation_type=c["correlation_type"],
            severity=c["severity"],
            confidence=c["confidence"],
            title=c["title"],
            description=c.get("description"),
            attack_pattern=c.get("attack_pattern"),
            plain_english=c.get("plain_english"),
            wazuh_alert_ids=c.get("wazuh_alert_ids", []),
            vulnerability_ids=c.get("vulnerability_ids", []),
        )
        for c in correlations
    ]

    summary = (
        f"Cross-domain correlation analysis found {len(correlations)} correlation(s), "
        f"of which {high_severity} are high or critical severity. "
    )
    if correlations:
        summary += "Immediate investigation is recommended for critical findings."
    else:
        summary += "No significant cross-domain attack patterns were detected."

    return CorrelateResult(
        org_id=org,
        correlations_found=len(correlations),
        high_severity_count=high_severity,
        correlations=correlation_responses,
        summary=summary,
    )


@router.get("/timeline/{org}", response_model=TimelineResponse)
async def get_timeline(
    org: str,
    hours: int = Query(default=24, ge=1, le=720),
) -> TimelineResponse:
    """Get unified threat timeline combining Wazuh and Digital Sentinel events."""
    if org not in data_store.organisations:
        raise HTTPException(status_code=404, detail=f"Organisation '{org}' not found")

    wazuh_alerts = data_store.get_wazuh_alerts(org)
    vulnerabilities = data_store.get_vulnerabilities(org)
    correlations = data_store.correlation_results.get(org, [])

    events = build_unified_timeline(wazuh_alerts, vulnerabilities, correlations)
    summary = generate_timeline_summary(events)

    timeline_events = [
        TimelineEvent(
            timestamp=e["timestamp"],
            source=e["source"],
            event_type=e["event_type"],
            severity=e["severity"],
            title=e["title"],
            description=e.get("description"),
            plain_english=e.get("plain_english"),
            related_ids=e.get("related_ids", []),
        )
        for e in events
    ]

    return TimelineResponse(
        org_id=org,
        time_range_hours=hours,
        total_events=len(timeline_events),
        events=timeline_events,
        summary=summary,
    )


@router.get("/alerts/{org}", response_model=list[WazuhAlertResponse])
async def get_wazuh_alerts(
    org: str,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[WazuhAlertResponse]:
    """Get recent Wazuh alerts with plain English translations."""
    if org not in data_store.organisations:
        raise HTTPException(status_code=404, detail=f"Organisation '{org}' not found")

    alerts = data_store.get_wazuh_alerts(org)[:limit]

    # Translate each alert
    for alert in alerts:
        if not alert.get("plain_english"):
            alert["plain_english"] = translate_wazuh_alert_to_plain_english(alert)

    return [
        WazuhAlertResponse(
            id=a.get("id", ""),
            wazuh_id=a.get("wazuh_id", ""),
            rule_id=a.get("rule_id", ""),
            rule_description=a.get("rule_description", ""),
            rule_level=a.get("rule_level", 0),
            agent_name=a.get("agent_name"),
            agent_ip=a.get("agent_ip"),
            source_ip=a.get("source_ip"),
            destination_ip=a.get("destination_ip"),
            category=a.get("category", "general"),
            plain_english=a.get("plain_english"),
            timestamp=a["timestamp"],
        )
        for a in alerts
    ]
