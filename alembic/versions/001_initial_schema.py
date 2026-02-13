"""Initial schema — all Digital Sentinel tables.

Revision ID: 001
Revises: None
Create Date: 2026-02-13
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organisations
    op.create_table(
        "organisations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(255), unique=True, nullable=False),
        sa.Column("industry_sector", sa.String(100), nullable=False, server_default="general"),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("overall_risk_score", sa.Float, server_default="0"),
        sa.Column("culture_score", sa.Float, server_default="0"),
        sa.Column("compliance_score", sa.Float, server_default="0"),
        sa.Column("vulnerability_count", sa.Integer, server_default="0"),
        sa.Column("remediation_velocity", sa.Float, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_organisations_slug", "organisations", ["slug"])

    # Vulnerabilities
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("cvss_score", sa.Float, server_default="0"),
        sa.Column("cve_id", sa.String(20), nullable=True),
        sa.Column("source", sa.String(100), nullable=False, server_default="digital_sentinel"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("asset", sa.String(500), nullable=True),
        sa.Column("remediated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vulnerabilities_org_id", "vulnerabilities", ["org_id"])

    # Assessments
    op.create_table(
        "assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("assessment_type", sa.String(50), nullable=False, server_default="full"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("overall_score", sa.Float, server_default="0"),
        sa.Column("vulnerability_count", sa.Integer, server_default="0"),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_assessments_org_id", "assessments", ["org_id"])

    # Wazuh connections
    op.create_table(
        "wazuh_connections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, unique=True),
        sa.Column("api_url", sa.String(500), nullable=False),
        sa.Column("api_user", sa.String(100), nullable=False),
        sa.Column("api_password_encrypted", sa.String(500), nullable=False),
        sa.Column("verify_ssl", sa.Boolean, server_default="true"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wazuh_connections_org_id", "wazuh_connections", ["org_id"])

    # Wazuh alerts
    op.create_table(
        "wazuh_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("wazuh_id", sa.String(100), nullable=False),
        sa.Column("rule_id", sa.String(20), nullable=False),
        sa.Column("rule_description", sa.String(500), nullable=False),
        sa.Column("rule_level", sa.Integer, server_default="0"),
        sa.Column("agent_name", sa.String(100), nullable=True),
        sa.Column("agent_ip", sa.String(45), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("category", sa.String(50), nullable=False, server_default="general"),
        sa.Column("plain_english", sa.Text, nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wazuh_alerts_org_id", "wazuh_alerts", ["org_id"])

    # Correlation results
    op.create_table(
        "correlation_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("correlation_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("confidence", sa.Float, server_default="0"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("wazuh_alert_ids", sa.Text, nullable=True),
        sa.Column("vulnerability_ids", sa.Text, nullable=True),
        sa.Column("attack_pattern", sa.String(100), nullable=True),
        sa.Column("plain_english", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_correlation_results_org_id", "correlation_results", ["org_id"])

    # Benchmark records
    op.create_table(
        "benchmark_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("industry_sector", sa.String(100), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),
        sa.Column("vulnerability_count", sa.Integer, server_default="0"),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("remediation_velocity", sa.Float, server_default="0"),
        sa.Column("culture_score", sa.Float, server_default="0"),
        sa.Column("compliance_score", sa.Float, server_default="0"),
        sa.Column("overall_risk_score", sa.Float, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_benchmark_records_org_id", "benchmark_records", ["org_id"])
    op.create_index("ix_benchmark_records_sector", "benchmark_records", ["industry_sector"])

    # Industry snapshots
    op.create_table(
        "industry_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("industry_sector", sa.String(100), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),
        sa.Column("org_count", sa.Integer, server_default="0"),
        sa.Column("avg_vulnerability_count", sa.Float, server_default="0"),
        sa.Column("avg_remediation_velocity", sa.Float, server_default="0"),
        sa.Column("avg_culture_score", sa.Float, server_default="0"),
        sa.Column("avg_compliance_score", sa.Float, server_default="0"),
        sa.Column("avg_risk_score", sa.Float, server_default="0"),
        sa.Column("median_vulnerability_count", sa.Float, server_default="0"),
        sa.Column("p25_risk_score", sa.Float, server_default="0"),
        sa.Column("p75_risk_score", sa.Float, server_default="0"),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_industry_snapshots_sector", "industry_snapshots", ["industry_sector"])


def downgrade() -> None:
    op.drop_table("industry_snapshots")
    op.drop_table("benchmark_records")
    op.drop_table("correlation_results")
    op.drop_table("wazuh_alerts")
    op.drop_table("wazuh_connections")
    op.drop_table("assessments")
    op.drop_table("vulnerabilities")
    op.drop_table("organisations")
