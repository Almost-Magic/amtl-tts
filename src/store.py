"""In-memory data store for Digital Sentinel.

Provides a simple data store used during development and testing.
In production, this would be backed by PostgreSQL/TimescaleDB.
"""

from __future__ import annotations

from typing import Any


class DataStore:
    """Thread-safe in-memory data store for development and testing."""

    def __init__(self) -> None:
        self.organisations: dict[str, dict[str, Any]] = {}
        self.vulnerabilities: dict[str, list[dict[str, Any]]] = {}  # org_id -> list
        self.assessments: dict[str, list[dict[str, Any]]] = {}
        self.wazuh_connections: dict[str, dict[str, Any]] = {}
        self.wazuh_alerts: dict[str, list[dict[str, Any]]] = {}  # org_id -> list
        self.correlation_results: dict[str, list[dict[str, Any]]] = {}
        self.benchmark_records: dict[str, list[dict[str, Any]]] = {}  # org_id -> list
        self.industry_snapshots: dict[str, dict[str, dict[str, Any]]] = {}  # sector -> period -> snapshot

    def reset(self) -> None:
        """Clear all data — used in tests."""
        self.__init__()

    def add_organisation(self, org_id: str, data: dict[str, Any]) -> None:
        """Add or update an organisation."""
        self.organisations[org_id] = data

    def get_vulnerabilities(self, org_id: str) -> list[dict[str, Any]]:
        """Get vulnerabilities for an organisation."""
        return self.vulnerabilities.get(org_id, [])

    def add_vulnerability(self, org_id: str, vuln: dict[str, Any]) -> None:
        """Add a vulnerability for an organisation."""
        self.vulnerabilities.setdefault(org_id, []).append(vuln)

    def get_wazuh_alerts(self, org_id: str) -> list[dict[str, Any]]:
        """Get Wazuh alerts for an organisation."""
        return self.wazuh_alerts.get(org_id, [])

    def add_wazuh_alert(self, org_id: str, alert: dict[str, Any]) -> None:
        """Add a Wazuh alert for an organisation."""
        self.wazuh_alerts.setdefault(org_id, []).append(alert)

    def get_benchmark_records(self, org_id: str) -> list[dict[str, Any]]:
        """Get benchmark records for an organisation."""
        return self.benchmark_records.get(org_id, [])

    def add_benchmark_record(self, org_id: str, record: dict[str, Any]) -> None:
        """Add a benchmark record for an organisation."""
        self.benchmark_records.setdefault(org_id, []).append(record)

    def get_sector_records(self, sector: str, period: str) -> list[dict[str, Any]]:
        """Get all benchmark records for a sector in a specific period."""
        records = []
        for org_id, org_records in self.benchmark_records.items():
            for record in org_records:
                if record.get("industry_sector") == sector and record.get("period") == period:
                    records.append(record)
        return records

    def get_all_sector_records(self, sector: str) -> list[dict[str, Any]]:
        """Get all benchmark records for a sector across all periods."""
        records = []
        for org_id, org_records in self.benchmark_records.items():
            for record in org_records:
                if record.get("industry_sector") == sector:
                    records.append(record)
        return records

    def get_sector_records_by_period(self, sector: str) -> dict[str, list[dict[str, Any]]]:
        """Get benchmark records grouped by period for a sector."""
        by_period: dict[str, list[dict[str, Any]]] = {}
        for org_id, org_records in self.benchmark_records.items():
            for record in org_records:
                if record.get("industry_sector") == sector:
                    period = record.get("period", "unknown")
                    by_period.setdefault(period, []).append(record)
        return by_period


# Global singleton — replaced in tests
data_store = DataStore()
