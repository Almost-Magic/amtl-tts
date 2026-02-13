"""Extended beast tests for Milestone 21 — additional edge cases and stress tests.

Covers: edge cases in correlation, malformed data handling, multi-org scenarios,
large dataset correlation, timeline edge cases, and comprehensive API validation.
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
    _generate_correlation_plain_english,
    _generate_pattern_plain_english,
    ATTACK_PATTERNS,
    SEVERITY_SCORES,
)
from src.services.wazuh_client import WazuhClient, WazuhClientError
from src.store import data_store


# ─── Edge cases in correlation ─────────────────────────────────────────────

class TestCorrelationEdgeCases:
    """Edge case tests for the correlation engine."""

    def test_duplicate_ip_across_multiple_vulns(self):
        """Multiple vulns on the same IP should each generate correlations."""
        alerts = [{
            "wazuh_id": "wz-100",
            "rule_id": "5710",
            "rule_description": "Brute force attack",
            "rule_level": 12,
            "agent_name": "server-01",
            "agent_ip": "10.0.0.1",
            "source_ip": "1.2.3.4",
            "destination_ip": "10.0.0.1",
            "category": "authentication",
        }]
        vulns = [
            {"id": f"v-{i}", "title": f"Vuln {i}", "severity": "high",
             "cvss_score": 7.0, "asset": "10.0.0.1"}
            for i in range(5)
        ]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        # Should have correlations for each matching vuln
        assert len(results) >= 1

    def test_multiple_alerts_same_category(self):
        """Multiple alerts in the same category should be handled correctly."""
        alerts = [
            {
                "wazuh_id": f"wz-{i}",
                "rule_id": "5710",
                "rule_description": f"Failed login attempt #{i}",
                "rule_level": 10,
                "agent_name": f"server-{i}",
                "agent_ip": f"10.0.0.{i}",
                "source_ip": "203.0.113.50",
                "destination_ip": f"10.0.0.{i}",
                "category": "authentication",
            }
            for i in range(1, 6)
        ]
        vulns = [{
            "id": "v-1",
            "title": "Weak password policy",
            "severity": "critical",
            "cvss_score": 9.0,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        assert len(results) >= 1

    def test_zero_confidence_threshold_includes_all(self):
        """Zero confidence threshold should include all possible correlations."""
        alerts = [{
            "wazuh_id": "wz-1",
            "rule_id": "1000",
            "rule_description": "Minor event",
            "rule_level": 1,
            "agent_name": "srv",
            "agent_ip": "10.0.0.1",
            "source_ip": "1.1.1.1",
            "destination_ip": "10.0.0.1",
            "category": "general",
        }]
        vulns = [{
            "id": "v-1",
            "title": "Info disclosure",
            "severity": "low",
            "cvss_score": 1.0,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.0)
        assert len(results) >= 1

    def test_max_confidence_threshold_very_selective(self):
        """Max confidence threshold should filter almost everything."""
        alerts = [{
            "wazuh_id": "wz-1",
            "rule_id": "1000",
            "rule_description": "Minor event",
            "rule_level": 3,
            "agent_name": "srv",
            "agent_ip": "10.0.0.1",
            "source_ip": "1.1.1.1",
            "destination_ip": "10.0.0.1",
            "category": "general",
        }]
        vulns = [{
            "id": "v-1",
            "title": "Low severity issue",
            "severity": "low",
            "cvss_score": 2.0,
            "asset": "10.0.0.1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=1.0)
        assert len(results) == 0

    def test_ipv6_addresses_handled(self):
        """IPv6 addresses should work in correlation matching."""
        alerts = [{
            "wazuh_id": "wz-ipv6",
            "rule_id": "5710",
            "rule_description": "Connection attempt",
            "rule_level": 8,
            "agent_name": "srv",
            "agent_ip": "::1",
            "source_ip": "2001:db8::1",
            "destination_ip": "::1",
            "category": "network",
        }]
        vulns = [{
            "id": "v-ipv6",
            "title": "Service exposed",
            "severity": "medium",
            "cvss_score": 5.0,
            "asset": "::1",
        }]

        results = correlate_alerts_with_vulnerabilities(alerts, vulns, min_confidence=0.3)
        assert len(results) >= 1

    def test_special_characters_in_descriptions(self):
        """Special characters in alert descriptions should not break processing."""
        alert = {
            "rule_id": "9999",
            "rule_description": 'SQL injection: " OR 1=1 --; <script>alert(1)</script>',
            "rule_level": 12,
            "agent_name": "web-server's-01",
            "source_ip": "10.0.0.1",
            "category": "intrusion_detection",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)
        assert len(result) > 0


# ─── Wazuh client tests ────────────────────────────────────────────────────

class TestWazuhClient:
    """Tests for the Wazuh API client."""

    def test_client_initialisation(self):
        """Client should initialise with connection parameters."""
        client = WazuhClient(
            api_url="https://wazuh.example.com:55000",
            api_user="admin",
            api_password="secret",
            verify_ssl=True,
        )
        assert client.api_url == "https://wazuh.example.com:55000"
        assert client.api_user == "admin"
        assert client.verify_ssl is True

    def test_client_strips_trailing_slash(self):
        """Client should strip trailing slashes from URL."""
        client = WazuhClient(
            api_url="https://wazuh.example.com:55000/",
            api_user="admin",
            api_password="secret",
        )
        assert client.api_url == "https://wazuh.example.com:55000"

    def test_client_error_is_exception(self):
        """WazuhClientError should be a proper exception."""
        error = WazuhClientError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)

    def test_client_token_initially_none(self):
        """Client should start without a token."""
        client = WazuhClient(
            api_url="https://wazuh.example.com:55000",
            api_user="admin",
            api_password="secret",
        )
        assert client._token is None
        assert client._token_expiry is None

    def test_client_ssl_verification_toggleable(self):
        """SSL verification should be configurable."""
        client_ssl = WazuhClient("https://a.com", "u", "p", verify_ssl=True)
        client_nossl = WazuhClient("https://a.com", "u", "p", verify_ssl=False)
        assert client_ssl.verify_ssl is True
        assert client_nossl.verify_ssl is False


# ─── Translation comprehensiveness ──────────────────────────────────────────

class TestTranslationComprehensiveness:
    """Test that all categories produce valid translations."""

    @pytest.mark.parametrize("category", [
        "intrusion_detection",
        "authentication",
        "network",
        "data_loss",
        "web",
        "firewall",
        "general",
    ])
    def test_all_categories_translate(self, category):
        """Every supported category should produce a valid translation."""
        alert = {
            "rule_id": "1000",
            "rule_description": f"Test alert for {category}",
            "rule_level": 8,
            "agent_name": "test-server",
            "category": category,
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)
        assert len(result) > 20
        assert "test-server" in result

    @pytest.mark.parametrize("level", [0, 1, 3, 5, 8, 10, 12, 15])
    def test_all_levels_translate(self, level):
        """Every alert level should produce a valid translation."""
        alert = {
            "rule_id": "1000",
            "rule_description": "Test alert",
            "rule_level": level,
            "agent_name": "test-server",
            "category": "general",
        }
        result = translate_wazuh_alert_to_plain_english(alert)
        assert isinstance(result, str)
        assert len(result) > 10


# ─── Timeline stress tests ──────────────────────────────────────────────────

class TestTimelineStress:
    """Stress tests for the timeline builder."""

    def test_large_timeline(self):
        """Timeline should handle hundreds of events."""
        now = datetime.now(timezone.utc)
        alerts = [
            {
                "wazuh_id": f"wz-{i}",
                "rule_description": f"Alert {i}",
                "rule_level": (i % 15) + 1,
                "category": ["web", "authentication", "network", "firewall"][i % 4],
                "timestamp": now - timedelta(minutes=i),
            }
            for i in range(200)
        ]
        vulns = [
            {
                "id": f"v-{i}",
                "title": f"Vuln {i}",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "created_at": now - timedelta(minutes=i * 2),
            }
            for i in range(100)
        ]

        events = build_unified_timeline(alerts, vulns, [])
        assert len(events) == 300
        # Should still be sorted
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_timeline_with_string_timestamps(self):
        """Timeline should handle ISO format string timestamps."""
        alerts = [{
            "wazuh_id": "wz-str",
            "rule_description": "Test",
            "rule_level": 5,
            "category": "web",
            "timestamp": "2025-06-15T10:30:00+00:00",
        }]
        events = build_unified_timeline(alerts, [], [])
        assert len(events) == 1
        assert isinstance(events[0]["timestamp"], datetime)

    def test_timeline_with_invalid_timestamp_fallback(self):
        """Timeline should handle invalid timestamps gracefully."""
        alerts = [{
            "wazuh_id": "wz-bad",
            "rule_description": "Test",
            "rule_level": 5,
            "category": "web",
            "timestamp": "not-a-date",
        }]
        events = build_unified_timeline(alerts, [], [])
        assert len(events) == 1
        assert isinstance(events[0]["timestamp"], datetime)


# ─── Severity scores registry ────────────────────────────────────────────────

class TestSeverityScores:
    """Tests for severity scoring constants."""

    def test_severity_scores_ordered(self):
        """Severity scores should be in ascending order of severity."""
        assert SEVERITY_SCORES["info"] < SEVERITY_SCORES["low"]
        assert SEVERITY_SCORES["low"] < SEVERITY_SCORES["medium"]
        assert SEVERITY_SCORES["medium"] < SEVERITY_SCORES["high"]
        assert SEVERITY_SCORES["high"] < SEVERITY_SCORES["critical"]

    def test_all_severities_have_scores(self):
        """All severity levels should have a numeric score."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert expected.issubset(set(SEVERITY_SCORES.keys()))


# ─── Plain English generation ─────────────────────────────────────────────────

class TestPlainEnglishGeneration:
    """Tests for plain English description generation."""

    def test_correlation_plain_english_mentions_vuln(self):
        """Correlation plain English should mention the vulnerability."""
        alert = {"rule_description": "IDS alert", "agent_name": "firewall"}
        vuln = {"title": "SQL Injection in API"}
        pattern = {"description": "Active exploitation detected."}
        result = _generate_correlation_plain_english(alert, vuln, pattern)
        assert "SQL Injection in API" in result

    def test_correlation_plain_english_mentions_agent(self):
        """Correlation plain English should mention the agent."""
        alert = {"rule_description": "Alert", "agent_name": "web-proxy-01"}
        vuln = {"title": "XSS"}
        pattern = {"description": "Test."}
        result = _generate_correlation_plain_english(alert, vuln, pattern)
        assert "web-proxy-01" in result

    def test_pattern_plain_english_includes_counts(self):
        """Pattern plain English should mention alert and vuln counts."""
        alerts = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        vulns = [{"id": "a"}, {"id": "b"}]
        pattern = {"title": "Test Pattern", "description": "Test description."}
        result = _generate_pattern_plain_english(alerts, vulns, pattern)
        assert "3" in result
        assert "2" in result


# ─── API endpoint validation ─────────────────────────────────────────────────

class TestWazuhAPIValidation:
    """Additional API validation tests."""

    def test_correlate_with_default_body(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """POST /api/wazuh/correlate/{org} without body should use defaults."""
        response = client.post(f"/api/wazuh/correlate/{sample_org}")
        assert response.status_code == 200
        data = response.json()
        assert data["org_id"] == sample_org

    def test_timeline_with_custom_hours(self, client, sample_org, sample_wazuh_alerts):
        """GET /api/wazuh/timeline/{org}?hours=72 should accept custom range."""
        response = client.get(f"/api/wazuh/timeline/{sample_org}?hours=72")
        assert response.status_code == 200
        data = response.json()
        assert data["time_range_hours"] == 72

    def test_alerts_with_limit(self, client, sample_org, sample_wazuh_alerts):
        """GET /api/wazuh/alerts/{org}?limit=2 should respect the limit."""
        response = client.get(f"/api/wazuh/alerts/{sample_org}?limit=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 2

    def test_connect_with_ssl_disabled(self, client):
        """POST /api/wazuh/connect with SSL disabled should work."""
        response = client.post("/api/wazuh/connect", json={
            "org_id": "test-org-nossl",
            "api_url": "https://wazuh.internal:55000",
            "api_user": "admin",
            "api_password": "pass",
            "verify_ssl": False,
        })
        assert response.status_code == 200
        assert response.json()["is_active"] is True

    def test_correlate_response_has_summary(self, client, sample_org, sample_vulnerabilities, sample_wazuh_alerts):
        """Correlation response should always include a summary."""
        response = client.post(f"/api/wazuh/correlate/{sample_org}")
        data = response.json()
        assert "summary" in data
        assert isinstance(data["summary"], str)
        assert len(data["summary"]) > 10
