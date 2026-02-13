"""Cross-domain correlation engine between Wazuh SIEM and Digital Sentinel."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


# Attack pattern definitions for cross-domain correlation
ATTACK_PATTERNS = {
    "external_scan_internal_alert": {
        "title": "External reconnaissance followed by internal alerts",
        "description": (
            "External vulnerability scanning activity detected by Digital Sentinel "
            "correlates with internal intrusion detection alerts from Wazuh, "
            "suggesting active exploitation attempts."
        ),
        "severity": "critical",
    },
    "credential_compromise": {
        "title": "Credential compromise spanning external and internal surfaces",
        "description": (
            "Exposed credentials detected externally correlate with "
            "authentication anomalies detected internally by Wazuh."
        ),
        "severity": "critical",
    },
    "lateral_movement": {
        "title": "External entry point with internal lateral movement",
        "description": (
            "External-facing vulnerability provides entry point, "
            "and Wazuh detects subsequent lateral movement internally."
        ),
        "severity": "high",
    },
    "data_exfiltration": {
        "title": "Potential data exfiltration via compromised service",
        "description": (
            "Vulnerable external service combined with unusual outbound "
            "traffic patterns detected by Wazuh."
        ),
        "severity": "critical",
    },
    "service_exploitation": {
        "title": "Active exploitation of known vulnerable service",
        "description": (
            "Known vulnerability in external service correlates with "
            "Wazuh alerts for that service indicating active exploitation."
        ),
        "severity": "high",
    },
    "dns_tunnelling": {
        "title": "Suspicious DNS activity correlating with external exposure",
        "description": (
            "Unusual DNS query patterns detected by Wazuh correlate with "
            "externally exposed DNS services found by Digital Sentinel."
        ),
        "severity": "medium",
    },
}

# Wazuh rule categories mapped to correlation types
WAZUH_CATEGORY_MAP = {
    "intrusion_detection": ["external_scan_internal_alert", "service_exploitation"],
    "authentication": ["credential_compromise"],
    "network": ["lateral_movement", "dns_tunnelling"],
    "data_loss": ["data_exfiltration"],
    "web": ["external_scan_internal_alert", "service_exploitation"],
    "syslog": ["lateral_movement"],
    "firewall": ["external_scan_internal_alert", "lateral_movement"],
}

# Severity to numeric mapping
SEVERITY_SCORES = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def translate_wazuh_alert_to_plain_english(alert: dict[str, Any]) -> str:
    """Translate a technical Wazuh alert into plain English for ELAINE briefings.

    Takes the raw Wazuh alert data and produces a human-readable summary
    suitable for non-technical stakeholders.
    """
    rule_id = alert.get("rule_id", "unknown")
    rule_desc = alert.get("rule_description", "Unknown alert")
    level = alert.get("rule_level", 0)
    agent = alert.get("agent_name", "an unknown system")
    source_ip = alert.get("source_ip")
    dest_ip = alert.get("destination_ip")
    category = alert.get("category", "general")

    # Determine urgency
    if level >= 12:
        urgency = "This is a critical security event requiring immediate attention"
    elif level >= 8:
        urgency = "This is a significant security event that should be investigated promptly"
    elif level >= 5:
        urgency = "This is a moderate security event worth monitoring"
    else:
        urgency = "This is a low-priority informational event"

    # Build the plain English description
    parts = [f"A security event was detected on {agent}."]

    # Category-specific descriptions
    category_descriptions = {
        "intrusion_detection": f"The intrusion detection system flagged suspicious activity (Rule {rule_id}: {rule_desc}).",
        "authentication": f"An authentication-related event occurred (Rule {rule_id}: {rule_desc}).",
        "network": f"Unusual network activity was detected (Rule {rule_id}: {rule_desc}).",
        "data_loss": f"A potential data loss event was identified (Rule {rule_id}: {rule_desc}).",
        "web": f"Web application security event detected (Rule {rule_id}: {rule_desc}).",
        "firewall": f"Firewall activity flagged (Rule {rule_id}: {rule_desc}).",
    }
    parts.append(
        category_descriptions.get(
            category,
            f"Security rule triggered (Rule {rule_id}: {rule_desc}).",
        )
    )

    if source_ip:
        parts.append(f"The activity originated from {source_ip}.")
    if dest_ip:
        parts.append(f"The target was {dest_ip}.")

    parts.append(f"{urgency}.")

    return " ".join(parts)


def classify_wazuh_alert_category(rule_id: str, rule_description: str, level: int) -> str:
    """Classify a Wazuh alert into a high-level category based on rule metadata."""
    desc_lower = rule_description.lower()

    if any(kw in desc_lower for kw in ["authentication", "login", "password", "credential", "brute"]):
        return "authentication"
    if any(kw in desc_lower for kw in ["intrusion", "ids", "attack", "exploit", "injection"]):
        return "intrusion_detection"
    if any(kw in desc_lower for kw in ["firewall", "iptables", "blocked", "denied"]):
        return "firewall"
    if any(kw in desc_lower for kw in ["web", "http", "apache", "nginx", "request"]):
        return "web"
    if any(kw in desc_lower for kw in ["dns", "network", "connection", "port", "scan"]):
        return "network"
    if any(kw in desc_lower for kw in ["data", "exfiltration", "transfer", "upload"]):
        return "data_loss"

    # Level-based fallback
    if level >= 10:
        return "intrusion_detection"
    return "general"


def correlate_alerts_with_vulnerabilities(
    wazuh_alerts: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    min_confidence: float = 0.5,
) -> list[dict[str, Any]]:
    """Correlate Wazuh alerts with Digital Sentinel vulnerability findings.

    This is the core correlation engine that detects attack patterns spanning
    internal (Wazuh) and external (Digital Sentinel) attack surfaces.

    Args:
        wazuh_alerts: List of Wazuh alert dicts with rule_id, rule_description, etc.
        vulnerabilities: List of vulnerability dicts with title, severity, asset, etc.
        min_confidence: Minimum confidence threshold (0.0-1.0) for including correlations.

    Returns:
        List of correlation result dicts.
    """
    correlations: list[dict[str, Any]] = []

    # Build lookup structures
    vuln_by_asset: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        asset = vuln.get("asset", "")
        if asset:
            vuln_by_asset.setdefault(asset, []).append(vuln)

    alert_by_category: dict[str, list[dict[str, Any]]] = {}
    for alert in wazuh_alerts:
        category = alert.get("category", "general")
        alert_by_category.setdefault(category, []).append(alert)

    # IP-based correlation: match Wazuh source/dest IPs to vulnerability assets
    for alert in wazuh_alerts:
        source_ip = alert.get("source_ip", "")
        dest_ip = alert.get("destination_ip", "")
        agent_ip = alert.get("agent_ip", "")
        alert_category = alert.get("category", "general")

        for ip in [source_ip, dest_ip, agent_ip]:
            if ip and ip in vuln_by_asset:
                matching_vulns = vuln_by_asset[ip]
                for vuln in matching_vulns:
                    # Calculate confidence based on severity alignment and timing
                    confidence = _calculate_correlation_confidence(alert, vuln)
                    if confidence >= min_confidence:
                        pattern_types = WAZUH_CATEGORY_MAP.get(alert_category, ["service_exploitation"])
                        pattern_key = pattern_types[0]
                        pattern = ATTACK_PATTERNS.get(pattern_key, ATTACK_PATTERNS["service_exploitation"])

                        correlations.append({
                            "id": str(uuid.uuid4()),
                            "correlation_type": pattern_key,
                            "severity": pattern["severity"],
                            "confidence": confidence,
                            "title": pattern["title"],
                            "description": pattern["description"],
                            "attack_pattern": pattern_key,
                            "wazuh_alert_ids": [alert.get("wazuh_id", alert.get("id", ""))],
                            "vulnerability_ids": [vuln.get("id", "")],
                            "plain_english": _generate_correlation_plain_english(alert, vuln, pattern),
                        })

    # Category-based correlation: detect patterns even without IP matches
    for category, alerts in alert_by_category.items():
        if category in WAZUH_CATEGORY_MAP and vulnerabilities:
            high_level_alerts = [a for a in alerts if a.get("rule_level", 0) >= 8]
            high_severity_vulns = [
                v for v in vulnerabilities
                if v.get("severity", "").lower() in ("critical", "high")
            ]

            if high_level_alerts and high_severity_vulns:
                pattern_keys = WAZUH_CATEGORY_MAP[category]
                for pattern_key in pattern_keys:
                    pattern = ATTACK_PATTERNS[pattern_key]
                    confidence = min(
                        0.4 + (len(high_level_alerts) * 0.05) + (len(high_severity_vulns) * 0.05),
                        0.95,
                    )
                    if confidence >= min_confidence:
                        correlations.append({
                            "id": str(uuid.uuid4()),
                            "correlation_type": pattern_key,
                            "severity": pattern["severity"],
                            "confidence": confidence,
                            "title": pattern["title"],
                            "description": pattern["description"],
                            "attack_pattern": pattern_key,
                            "wazuh_alert_ids": [a.get("wazuh_id", a.get("id", "")) for a in high_level_alerts[:5]],
                            "vulnerability_ids": [v.get("id", "") for v in high_severity_vulns[:5]],
                            "plain_english": _generate_pattern_plain_english(
                                high_level_alerts, high_severity_vulns, pattern
                            ),
                        })

    # Deduplicate by correlation_type + overlapping IDs
    seen: set[str] = set()
    unique_correlations: list[dict[str, Any]] = []
    for corr in correlations:
        key = f"{corr['correlation_type']}:{','.join(sorted(corr['wazuh_alert_ids']))}"
        if key not in seen:
            seen.add(key)
            unique_correlations.append(corr)

    # Sort by severity then confidence
    unique_correlations.sort(
        key=lambda c: (SEVERITY_SCORES.get(c["severity"], 0), c["confidence"]),
        reverse=True,
    )

    return unique_correlations


def _calculate_correlation_confidence(alert: dict, vuln: dict) -> float:
    """Calculate confidence score for an alert-vulnerability correlation."""
    confidence = 0.3  # Base confidence for IP match

    # Higher Wazuh alert level = higher confidence
    level = alert.get("rule_level", 0)
    confidence += min(level * 0.04, 0.3)

    # Higher vulnerability severity = higher confidence
    severity = vuln.get("severity", "medium").lower()
    severity_bonus = {"critical": 0.25, "high": 0.2, "medium": 0.1, "low": 0.05}
    confidence += severity_bonus.get(severity, 0.05)

    # CVSS score bonus
    cvss = vuln.get("cvss_score", 0)
    confidence += min(cvss * 0.02, 0.15)

    return min(confidence, 1.0)


def _generate_correlation_plain_english(
    alert: dict, vuln: dict, pattern: dict
) -> str:
    """Generate plain English description for an alert-vulnerability correlation."""
    vuln_title = vuln.get("title", "a known vulnerability")
    alert_desc = alert.get("rule_description", "a security event")
    agent = alert.get("agent_name", "a monitored system")

    return (
        f"We detected a connection between an external vulnerability ({vuln_title}) "
        f"and an internal security event on {agent} ({alert_desc}). "
        f"This pattern suggests {pattern['description'].lower()} "
        f"This correlation warrants immediate investigation."
    )


def _generate_pattern_plain_english(
    alerts: list[dict], vulns: list[dict], pattern: dict
) -> str:
    """Generate plain English for a category-level pattern correlation."""
    alert_count = len(alerts)
    vuln_count = len(vulns)

    return (
        f"Analysis of {alert_count} internal security alert(s) and {vuln_count} "
        f"external vulnerability finding(s) indicates a potential "
        f"{pattern['title'].lower()}. {pattern['description']} "
        f"Review both internal and external findings for coordinated response."
    )


def build_unified_timeline(
    wazuh_alerts: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a unified threat timeline combining Wazuh and Digital Sentinel events.

    Merges events from both sources into a single chronological timeline,
    annotating correlated events.

    Returns:
        List of timeline event dicts sorted by timestamp (newest first).
    """
    events: list[dict[str, Any]] = []

    # Add Wazuh alerts to timeline
    for alert in wazuh_alerts:
        timestamp = alert.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except (ValueError, TypeError):
                timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)

        # Check if this alert is part of a correlation
        related_ids = []
        for corr in correlations:
            alert_id = alert.get("wazuh_id", alert.get("id", ""))
            if alert_id in corr.get("wazuh_alert_ids", []):
                related_ids.append(corr["id"])

        events.append({
            "timestamp": timestamp,
            "source": "wazuh",
            "event_type": alert.get("category", "general"),
            "severity": _wazuh_level_to_severity(alert.get("rule_level", 0)),
            "title": alert.get("rule_description", "Unknown alert"),
            "description": alert.get("rule_description"),
            "plain_english": alert.get("plain_english"),
            "related_ids": related_ids,
        })

    # Add vulnerabilities to timeline
    for vuln in vulnerabilities:
        timestamp = vuln.get("created_at")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except (ValueError, TypeError):
                timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)

        related_ids = []
        for corr in correlations:
            if vuln.get("id", "") in corr.get("vulnerability_ids", []):
                related_ids.append(corr["id"])

        events.append({
            "timestamp": timestamp,
            "source": "digital_sentinel",
            "event_type": "vulnerability",
            "severity": vuln.get("severity", "medium"),
            "title": vuln.get("title", "Unknown vulnerability"),
            "description": vuln.get("description"),
            "plain_english": None,
            "related_ids": related_ids,
        })

    # Add correlations as meta-events
    for corr in correlations:
        events.append({
            "timestamp": datetime.now(timezone.utc),
            "source": "correlation",
            "event_type": corr.get("correlation_type", "unknown"),
            "severity": corr.get("severity", "medium"),
            "title": corr.get("title", "Unknown correlation"),
            "description": corr.get("description"),
            "plain_english": corr.get("plain_english"),
            "related_ids": corr.get("wazuh_alert_ids", []) + corr.get("vulnerability_ids", []),
        })

    # Sort by timestamp descending (newest first)
    events.sort(key=lambda e: e["timestamp"], reverse=True)

    return events


def _wazuh_level_to_severity(level: int) -> str:
    """Convert Wazuh numeric alert level to severity string."""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def generate_timeline_summary(events: list[dict[str, Any]]) -> str:
    """Generate a plain English summary of the unified timeline."""
    if not events:
        return "No security events found in the specified time range."

    total = len(events)
    wazuh_count = sum(1 for e in events if e["source"] == "wazuh")
    sentinel_count = sum(1 for e in events if e["source"] == "digital_sentinel")
    correlation_count = sum(1 for e in events if e["source"] == "correlation")
    critical_count = sum(1 for e in events if e.get("severity") == "critical")
    high_count = sum(1 for e in events if e.get("severity") == "high")

    parts = [f"Timeline contains {total} events: {wazuh_count} internal (Wazuh), "
             f"{sentinel_count} external (Digital Sentinel), and {correlation_count} "
             f"cross-domain correlations."]

    if critical_count:
        parts.append(f"{critical_count} critical severity event(s) require immediate attention.")
    if high_count:
        parts.append(f"{high_count} high severity event(s) should be investigated promptly.")

    if correlation_count:
        parts.append(
            "Cross-domain correlations indicate activity spanning both internal "
            "and external attack surfaces — coordinated response recommended."
        )

    return " ".join(parts)
