"""Shared test fixtures for Digital Sentinel test suite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from src.app import create_app
from src.config import Settings
from src.store import DataStore, data_store


def _test_settings() -> Settings:
    """Return settings suitable for testing."""
    return Settings(
        environment="development",
        debug=True,
        log_format="console",
        rate_limit_default="1000/minute",
        rate_limit_burst="2000/minute",
        allowed_origins="http://localhost:3000,http://localhost:5015",
    )


@pytest.fixture
def settings():
    """Test settings."""
    return _test_settings()


@pytest.fixture
def app(settings):
    """Create a fresh FastAPI app for testing."""
    return create_app(settings)


@pytest.fixture
def client(app):
    """HTTP test client."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    """Reset the global data store before each test."""
    data_store.reset()
    yield
    data_store.reset()


@pytest.fixture
def sample_org():
    """Create a sample organisation in the data store."""
    org_id = "acme-corp"
    data_store.add_organisation(org_id, {
        "id": org_id,
        "name": "ACME Corporation",
        "slug": org_id,
        "industry_sector": "technology",
        "domain": "acme.example.com",
        "overall_risk_score": 65.0,
        "culture_score": 72.0,
        "compliance_score": 80.0,
        "vulnerability_count": 15,
        "remediation_velocity": 3.5,
    })
    return org_id


@pytest.fixture
def sample_vulnerabilities(sample_org):
    """Create sample vulnerabilities for the sample org."""
    vulns = [
        {
            "id": str(uuid.uuid4()),
            "org_id": sample_org,
            "title": "SQL Injection in login endpoint",
            "description": "The login form is vulnerable to SQL injection attacks.",
            "severity": "critical",
            "cvss_score": 9.8,
            "cve_id": "CVE-2024-1234",
            "source": "digital_sentinel",
            "status": "open",
            "asset": "10.0.0.1",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=12),
        },
        {
            "id": str(uuid.uuid4()),
            "org_id": sample_org,
            "title": "Outdated TLS configuration",
            "description": "Server supports TLS 1.0 which is deprecated.",
            "severity": "high",
            "cvss_score": 7.5,
            "cve_id": None,
            "source": "digital_sentinel",
            "status": "open",
            "asset": "10.0.0.2",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=6),
        },
        {
            "id": str(uuid.uuid4()),
            "org_id": sample_org,
            "title": "Missing security headers",
            "description": "X-Content-Type-Options and CSP headers are missing.",
            "severity": "medium",
            "cvss_score": 5.0,
            "cve_id": None,
            "source": "digital_sentinel",
            "status": "open",
            "asset": "10.0.0.3",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=3),
        },
    ]
    for vuln in vulns:
        data_store.add_vulnerability(sample_org, vuln)
    return vulns


@pytest.fixture
def sample_wazuh_alerts(sample_org):
    """Create sample Wazuh alerts for the sample org."""
    alerts = [
        {
            "id": str(uuid.uuid4()),
            "wazuh_id": "wz-001",
            "org_id": sample_org,
            "rule_id": "5710",
            "rule_description": "sshd: Attempt to login using a denied user.",
            "rule_level": 10,
            "agent_name": "web-server-01",
            "agent_ip": "10.0.0.1",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "category": "authentication",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=8),
        },
        {
            "id": str(uuid.uuid4()),
            "wazuh_id": "wz-002",
            "org_id": sample_org,
            "rule_id": "31104",
            "rule_description": "Web server 400 error code.",
            "rule_level": 5,
            "agent_name": "web-server-01",
            "agent_ip": "10.0.0.1",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.0.1",
            "category": "web",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=4),
        },
        {
            "id": str(uuid.uuid4()),
            "wazuh_id": "wz-003",
            "org_id": sample_org,
            "rule_id": "100002",
            "rule_description": "Multiple IDS alerts from same source IP.",
            "rule_level": 13,
            "agent_name": "ids-sensor-01",
            "agent_ip": "10.0.0.5",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.0.1",
            "category": "intrusion_detection",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
        },
        {
            "id": str(uuid.uuid4()),
            "wazuh_id": "wz-004",
            "org_id": sample_org,
            "rule_id": "80710",
            "rule_description": "Firewall: Blocked outbound connection to known malicious IP.",
            "rule_level": 14,
            "agent_name": "firewall-01",
            "agent_ip": "10.0.0.254",
            "source_ip": "10.0.0.1",
            "destination_ip": "198.51.100.99",
            "category": "firewall",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=1),
        },
    ]
    for alert in alerts:
        data_store.add_wazuh_alert(sample_org, alert)
    return alerts


@pytest.fixture
def sample_benchmark_data(sample_org):
    """Create sample benchmark data across multiple orgs and periods."""
    orgs = [
        ("acme-corp", "technology", 15, 2, 5, 3.5, 72.0, 80.0, 65.0),
        ("beta-inc", "technology", 22, 4, 8, 2.1, 58.0, 65.0, 78.0),
        ("gamma-ltd", "technology", 8, 0, 3, 5.0, 85.0, 92.0, 35.0),
        ("delta-co", "technology", 30, 6, 12, 1.5, 45.0, 55.0, 88.0),
        ("epsilon-io", "technology", 12, 1, 4, 4.2, 78.0, 88.0, 50.0),
        ("zeta-fin", "financial_services", 18, 3, 7, 3.0, 70.0, 85.0, 60.0),
        ("eta-fin", "financial_services", 25, 5, 10, 2.5, 62.0, 78.0, 72.0),
        ("theta-fin", "financial_services", 10, 1, 3, 4.8, 82.0, 95.0, 40.0),
    ]

    periods = ["2025-07", "2025-08", "2025-09", "2025-10", "2025-11", "2025-12"]

    for org_slug, sector, vuln_count, crit, high, velocity, culture, compliance, risk in orgs:
        if org_slug != sample_org:
            data_store.add_organisation(org_slug, {
                "id": org_slug,
                "name": org_slug.replace("-", " ").title(),
                "slug": org_slug,
                "industry_sector": sector,
                "overall_risk_score": risk,
                "culture_score": culture,
                "compliance_score": compliance,
                "vulnerability_count": vuln_count,
                "remediation_velocity": velocity,
            })

        for i, period in enumerate(periods):
            # Add some variation over time
            drift = i * 0.5
            record = {
                "org_id": org_slug,
                "industry_sector": sector,
                "period": period,
                "vulnerability_count": max(0, vuln_count + i - 3),
                "critical_count": max(0, crit + (i % 2) - 1),
                "high_count": max(0, high + i - 2),
                "medium_count": vuln_count // 2,
                "low_count": vuln_count // 3,
                "remediation_velocity": round(velocity + drift * 0.1, 2),
                "culture_score": round(culture + drift, 2),
                "compliance_score": round(compliance + drift * 0.5, 2),
                "overall_risk_score": round(max(0, risk - drift), 2),
            }
            data_store.add_benchmark_record(org_slug, record)

    return periods
