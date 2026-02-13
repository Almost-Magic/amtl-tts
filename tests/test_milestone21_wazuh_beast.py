"""Beast tests for Milestone 21 — Wazuh Cross-Domain Correlation.

Tests cover: correlation logic, timeline generation, alert translation,
API endpoints, attack pattern detection, and edge cases.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from src.services.wazuh_correlation import (
    build_unified_timeline,
    classify_wazuh_alert_category,
    correlate_alerts_with_vulnerabilities,
    generate_timeline_summary,
    translate_wazuh_alert_to_plain_english,
    _calculate_correlation_confidence,
    _wazuh_level_to_severity,
    ATTACK_PATTERNS,
    WAZUH_CATEGORY_MAP,
)
from src.store import data_store


# ─── Test 1: Alert translation to plain English ───────────────────────────────

class TestAlertTranslation:
    """Tests for translating Wazuh alerts to plain English."""

    def test_critical_alert_translation(self):
        """Critical alerts (level >= 12) should produce urgent language."""
        alert = {
            "rule_id": "5710",
            "rule_description": "sshd: Attempt to login using a denied user.",
            "rule_level": 14,
            "agent_name": "web-server-01",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "category": "authentication",
        }
        result = translate_wazuh_alert_to_plain_english(alert)

        assert "web-server-01" in result
        assert "immediate attention" in result.lower()
        assert "192.168.1.100" in result

    def test_moderate_alert_translation(self):
        """Moderate alerts (level 5-7) should produce monitoring language."""
        alert = {
            "rule_id": "31104",
            "rule_description": "Web server 400 error code.",
            "rule_level": 5,
            "agent_name": "api-gateway",
            "category": "web",
        }
        result = translate_wazuh_alert_to_plain_english(alert)

        assert "api-gateway" in result
        assert "moderate" in result.lower() or "monitoring" in result.lower()

    def test_low_priority_alert_translation(self):
        """Low-priority alerts (level < 5) should be informational."""
        alert = {
            "rule_id": "1001",
            "rule_description": "Successful login.",
            "rule_level": 2,
            "agent_name": "mail-server",
            "category": "authentication",
        }
        result = translate_wazuh_alert_to_plain_english(alert)

        assert "informational" in result.lower() or "low-priority" in result.lower()

    def test_translation_includes_source_ip(self):
        """Translation should mention source IP when available."""
        alert = {
            "rule_id": "5001",
            "rule_description": "Brute force attack.",
            "rule_level": 10,
            "agent_name": "server-01",
            "source_ip": "203.0.113.42",
            "category": "authentication",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert "203.0.113.42" in result

    def test_translation_includes_destination_ip(self):
        """Translation should mention destination IP when available."""
        alert = {
            "rule_id": "5001",
            "rule_description": "Network scan detected.",
            "rule_level": 8,
            "agent_name": "firewall",
            "destination_ip": "10.0.0.50",
            "category": "network",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert "10.0.0.50" in result

    def test_translation_handles_missing_fields(self):
        """Translation should handle missing optional fields gracefully."""
        alert = {
            "rule_id": "9999",
            "rule_description": "Unknown event.",
            "rule_level": 3,
            "category": "general",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)
        assert len(result) > 10


# ─── Test 2: Alert category classification ─────────────────────────────────────

class TestAlertClassification:
    """Tests for classifying Wazuh alerts into categories."""

    def test_authentication_classification(self):
        """Authentication-related alerts should be classified correctly."""
        assert classify_wazuh_alert_category("5710", "Failed password for root", 5) == "authentication"
        assert classify_wazuh_alert_category("5000", "Brute force login attempt", 8) == "authentication"

    def test_intrusion_detection_classification(self):
        """IDS alerts should be classified correctly."""
        assert classify_wazuh_alert_category("100001", "IDS attack detected", 10) == "intrusion_detection"
        assert classify_wazuh_alert_category("100002", "SQL injection exploit attempt", 12) == "intrusion_detection"

    def test_network_classification(self):
        """Network alerts should be classified correctly."""
        assert classify_wazuh_alert_category("3001", "Network port scan detected", 6) == "network"
        assert classify_wazuh_alert_category("3002", "DNS query anomaly", 5) == "network"

    def test_firewall_classification(self):
        """Firewall alerts should be classified correctly."""
        assert classify_wazuh_alert_category("8001", "Firewall blocked connection", 7) == "firewall"
        assert classify_wazuh_alert_category("8002", "iptables denied packet", 4) == "firewall"

    def test_web_classification(self):
        """Web alerts should be classified correctly."""
        assert classify_wazuh_alert_category("31001", "Apache HTTP request anomaly", 5) == "web"
        assert classify_wazuh_alert_category("31002", "nginx error detected", 3) == "web"

    def test_high_level_unknown_defaults_to_intrusion(self):
        """High-level unclassified alerts should default to intrusion_detection."""
        assert classify_wazuh_alert_category("99999", "Unknown high severity event", 12) == "intrusion_detection"

    def test_low_level_unknown_defaults_to_general(self):
        """Low-level unclassified alerts should default to general."""
        assert classify_wazuh_alert_category("99999", "Routine system check", 2) == "general"


# ─── Test 3: Correlation engine ───────────────────────────────────────────────

class TestCorrelationEngine:
    """Tests for the cross-domain correlation engine."""

    def test_ip_based_correlation(self):
        """Alerts and vulns sharing an IP should be correlated."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_id": "5710",
            "rule_description": "Denied login attempt",
            "rule_level": 10,
            "agent_name": "server-01",
            "agent_ip": "10.0.0.1",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "category": "authentication",
        }]
        vulns = [{
            "id": "vuln-001",
            "title": "SQL Injection",
            "severity": "critical",
            "cvss_score": 9.8,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        assert len(results) >= 1
        assert any(r["severity"] in ("critical", "high") for r in results)

    def test_no_correlation_without_matching_ips(self):
        """Alerts and vulns with no common IPs should have fewer correlations."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_id": "5710",
            "rule_description": "Denied login attempt",
            "rule_level": 3,
            "agent_name": "server-01",
            "agent_ip": "10.0.0.99",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.99",
            "category": "general",
        }]
        vulns = [{
            "id": "vuln-001",
            "title": "Missing header",
            "severity": "low",
            "cvss_score": 2.0,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.8)
        # No IP match + low severity + high threshold = no correlations
        assert len(results) == 0

    def test_confidence_threshold_filtering(self):
        """Only correlations above the confidence threshold should be returned."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_id": "5710",
            "rule_description": "Minor event",
            "rule_level": 2,
            "agent_name": "server-01",
            "agent_ip": "10.0.0.1",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "category": "general",
        }]
        vulns = [{
            "id": "vuln-001",
            "title": "Info disclosure",
            "severity": "low",
            "cvss_score": 1.0,
            "asset": "10.0.0.1",
        }]

        # High threshold should filter out weak correlations
        results_high = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.9)
        results_low = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.1)
        assert len(results_high) <= len(results_low)

    def test_category_based_correlation(self):
        """High-severity alerts and vulns should correlate even without IP match."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_id": "100002",
            "rule_description": "Multiple IDS alerts from same source",
            "rule_level": 13,
            "agent_name": "ids-01",
            "agent_ip": "10.0.0.5",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.0.5",
            "category": "intrusion_detection",
        }]
        vulns = [{
            "id": "vuln-001",
            "title": "Critical RCE vulnerability",
            "severity": "critical",
            "cvss_score": 10.0,
            "asset": "10.0.0.99",  # Different IP
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        # Should find category-based correlation
        assert len(results) >= 1

    def test_correlation_results_sorted_by_severity(self):
        """Results should be sorted by severity (critical first)."""
        alerts = [
            {
                "wazuh_id": "wz-001",
                "rule_id": "5001",
                "rule_description": "Login denied",
                "rule_level": 10,
                "agent_name": "s1",
                "agent_ip": "10.0.0.1",
                "source_ip": "1.2.3.4",
                "destination_ip": "10.0.0.1",
                "category": "authentication",
            },
            {
                "wazuh_id": "wz-002",
                "rule_id": "100002",
                "rule_description": "IDS attack",
                "rule_level": 14,
                "agent_name": "s2",
                "agent_ip": "10.0.0.2",
                "source_ip": "1.2.3.4",
                "destination_ip": "10.0.0.2",
                "category": "intrusion_detection",
            },
        ]
        vulns = [
            {
                "id": "v1",
                "title": "Critical vuln",
                "severity": "critical",
                "cvss_score": 10.0,
                "asset": "10.0.0.1",
            },
            {
                "id": "v2",
                "title": "High vuln",
                "severity": "high",
                "cvss_score": 7.0,
                "asset": "10.0.0.2",
            },
        ]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        if len(results) >= 2:
            severities = [r["severity"] for r in results]
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            severity_indices = [severity_order.get(s, 4) for s in severities]
            assert severity_indices == sorted(severity_indices)

    def test_empty_inputs(self):
        """Correlation with empty inputs should return empty results."""
        assert correlate_alerts_with_vulnerabilities([], [], 0.5) == []
        assert correlate_alerts_with_vulnerabilities([], [{"id": "v1"}], 0.5) == []
        assert correlate_alerts_with_vulnerabilities([{"wazuh_id": "a1"}], [], 0.5) == []

    def test_correlation_plain_english_generated(self):
        """Each correlation should have a plain English explanation."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_id": "5710",
            "rule_description": "SSH brute force",
            "rule_level": 12,
            "agent_name": "bastion-host",
            "agent_ip": "10.0.0.1",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "category": "authentication",
        }]
        vulns = [{
            "id": "vuln-001",
            "title": "Exposed SSH service",
            "severity": "high",
            "cvss_score": 7.5,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        for r in results:
            assert r.get("plain_english")
            assert len(r["plain_english"]) > 20


# ─── Test 4: Unified timeline ────────────────────────────────────────────────

class TestUnifiedTimeline:
    """Tests for building and summarising the unified threat timeline."""

    def test_timeline_merges_sources(self):
        """Timeline should contain events from both Wazuh and Digital Sentinel."""
        alerts = [{
            "wazuh_id": "wz-001",
            "rule_description": "Alert 1",
            "rule_level": 5,
            "category": "web",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
        }]
        vulns = [{
            "id": "v-001",
            "title": "Vuln 1",
            "severity": "medium",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=1),
        }]

        events = build_unified_timeline(alerts, vulns, [])
        sources = {e["source"] for e in events}
        assert "wazuh" in sources
        assert "digital_sentinel" in sources

    def test_timeline_sorted_by_timestamp_descending(self):
        """Timeline events should be sorted newest first."""
        now = datetime.now(timezone.utc)
        alerts = [
            {"wazuh_id": "wz-old", "rule_description": "Old", "rule_level": 3,
             "category": "web", "timestamp": now - timedelta(hours=10)},
            {"wazuh_id": "wz-new", "rule_description": "New", "rule_level": 3,
             "category": "web", "timestamp": now - timedelta(hours=1)},
        ]

        events = build_unified_timeline(alerts, [], [])
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_timeline_includes_correlation_events(self):
        """Correlations should appear in the timeline."""
        correlations = [{
            "id": "corr-001",
            "correlation_type": "service_exploitation",
            "severity": "high",
            "title": "Active exploitation detected",
            "description": "Test correlation",
            "plain_english": "Test explanation",
            "wazuh_alert_ids": ["wz-001"],
            "vulnerability_ids": ["v-001"],
        }]

        events = build_unified_timeline([], [], correlations)
        assert any(e["source"] == "correlation" for e in events)

    def test_timeline_summary_counts(self):
        """Summary should accurately count events by source."""
        alerts = [
            {"wazuh_id": f"wz-{i}", "rule_description": f"Alert {i}",
             "rule_level": 5, "category": "web",
             "timestamp": datetime.now(timezone.utc)}
            for i in range(5)
        ]
        vulns = [
            {"id": f"v-{i}", "title": f"Vuln {i}", "severity": "medium",
             "created_at": datetime.now(timezone.utc)}
            for i in range(3)
        ]

        events = build_unified_timeline(alerts, vulns, [])
        summary = generate_timeline_summary(events)
        assert "5" in summary  # Wazuh count
        assert "3" in summary  # Sentinel count

    def test_empty_timeline_summary(self):
        """Empty timeline should produce a meaningful message."""
        summary = generate_timeline_summary([])
        assert "no security events" in summary.lower()

    def test_timeline_related_ids_populated(self):
        """Correlated events should have related IDs populated."""
        correlations = [{
            "id": "corr-001",
            "correlation_type": "test",
            "severity": "medium",
            "title": "Test",
            "wazuh_alert_ids": ["wz-001"],
            "vulnerability_ids": ["v-001"],
        }]
        alerts = [{
            "wazuh_id": "wz-001",
            "id": "alert-internal-id",
            "rule_description": "Test alert",
            "rule_level": 5,
            "category": "web",
            "timestamp": datetime.now(timezone.utc),
        }]

        events = build_unified_timeline(alerts, [], correlations)
        wazuh_events = [e for e in events if e["source"] == "wazuh"]
        for we in wazuh_events:
            if we["title"] == "Test alert":
                assert "corr-001" in we["related_ids"]


# ─── Test 5: Wazuh severity mapping ──────────────────────────────────────────

class TestSeverityMapping:
    """Tests for Wazuh level to severity conversion."""

    def test_critical_level(self):
        assert _wazuh_level_to_severity(15) == "critical"
        assert _wazuh_level_to_severity(12) == "critical"

    def test_high_level(self):
        assert _wazuh_level_to_severity(11) == "high"
        assert _wazuh_level_to_severity(8) == "high"

    def test_medium_level(self):
        assert _wazuh_level_to_severity(7) == "medium"
        assert _wazuh_level_to_severity(5) == "medium"

    def test_low_level(self):
        assert _wazuh_level_to_severity(4) == "low"
        assert _wazuh_level_to_severity(3) == "low"

    def test_info_level(self):
        assert _wazuh_level_to_severity(2) == "info"
        assert _wazuh_level_to_severity(0) == "info"


# ─── Test 6: Confidence scoring ──────────────────────────────────────────────

class TestConfidenceScoring:
    """Tests for correlation confidence calculation."""

    def test_high_severity_high_level_gives_high_confidence(self):
        """Critical vuln + high alert level = high confidence."""
        alert = {"rule_level": 14}
        vuln = {"severity": "critical", "cvss_score": 9.8}
        confidence = _calculate_correlation_confidence(alert, vuln)
        assert confidence >= 0.7

    def test_low_severity_low_level_gives_low_confidence(self):
        """Low vuln + low alert level = low confidence."""
        alert = {"rule_level": 2}
        vuln = {"severity": "low", "cvss_score": 1.0}
        confidence = _calculate_correlation_confidence(alert, vuln)
        assert confidence <= 0.5

    def test_confidence_capped_at_one(self):
        """Confidence should never exceed 1.0."""
        alert = {"rule_level": 15}
        vuln = {"severity": "critical", "cvss_score": 10.0}
        confidence = _calculate_correlation_confidence(alert, vuln)
        assert confidence <= 1.0


# ─── Test 7: API endpoints ───────────────────────────────────────────────────

class TestWazuhAPIEndpoints:
    """Tests for Wazuh API endpoints."""

    def test_connect_endpoint(self, client):
        """POST /api/wazuh/connect should configure a connection."""
        response = client.post("/api/wazuh/connect", json={
            "org_id": "test-org",
            "api_url": "https://wazuh.example.com:55000",
            "api_user": "admin",
            "api_password": "secret",
            "verify_ssl": True,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == "test-org"
        assert data["is_active"] is True
        assert "successfully" in data["message"].lower()

    def test_correlate_endpoint(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """POST /api/wazuh/correlate/{org} should return correlations."""
        response = client.post(f"/api/wazuh/correlate/{sample_org}", json={
            "time_range_hours": 24,
            "min_confidence": 0.3,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == sample_org
        assert "correlations_found" in data
        assert isinstance(data["correlations"], list)
        assert "summary" in data

    def test_correlate_unknown_org_returns_404(self, client):
        """Correlation request for unknown org should return 404."""
        response = client.post("/api/wazuh/correlate/nonexistent-org")
        assert response.status_code == 404

    def test_timeline_endpoint(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """GET /api/wazuh/timeline/{org} should return a timeline."""
        response = client.get(f"/api/wazuh/timeline/{sample_org}")
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == sample_org
        assert data["total_events"] > 0
        assert isinstance(data["events"], list)
        assert "summary" in data

    def test_timeline_unknown_org_returns_404(self, client):
        """Timeline request for unknown org should return 404."""
        response = client.get("/api/wazuh/timeline/nonexistent-org")
        assert response.status_code == 404

    def test_alerts_endpoint(self, client, sample_org, sample_wazuh_alerts):
        """GET /api/wazuh/alerts/{org} should return translated alerts."""
        response = client.get(f"/api/wazuh/alerts/{sample_org}")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        for alert in data:
            assert "plain_english" in alert
            assert alert["plain_english"] is not None

    def test_alerts_unknown_org_returns_404(self, client):
        """Alerts request for unknown org should return 404."""
        response = client.get("/api/wazuh/alerts/nonexistent-org")
        assert response.status_code == 404


# ─── Test 8: Attack patterns registry ────────────────────────────────────────

class TestAttackPatterns:
    """Tests for the attack patterns configuration."""

    def test_all_patterns_have_required_fields(self):
        """Every attack pattern must have title, description, and severity."""
        for key, pattern in ATTACK_PATTERNS.items():
            assert "title" in pattern, f"Pattern {key} missing title"
            assert "description" in pattern, f"Pattern {key} missing description"
            assert "severity" in pattern, f"Pattern {key} missing severity"
            assert pattern["severity"] in ("critical", "high", "medium", "low", "info")

    def test_category_map_references_valid_patterns(self):
        """Every pattern in WAZUH_CATEGORY_MAP must exist in ATTACK_PATTERNS."""
        for category, patterns in WAZUH_CATEGORY_MAP.items():
            for pattern_key in patterns:
                assert pattern_key in ATTACK_PATTERNS, (
                    f"Category {category} references unknown pattern {pattern_key}"
                )

    def test_minimum_pattern_count(self):
        """There should be at least 5 attack patterns defined."""
        assert len(ATTACK_PATTERNS) >= 5
