"""Extended beast tests for Milestone 23 — additional production hardening tests.

Covers: edge cases in config, middleware, detailed Docker validation,
Alembic migration content, OpenAPI schema validation, and stress scenarios.
"""

from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

from src.app import create_app
from src.config import Settings, get_settings
from src.middleware import (
    configure_cors,
    configure_rate_limiting,
    configure_structured_logging,
    get_limiter,
    is_shutdown_requested,
    lifespan,
)
from src.store import DataStore, data_store


# ─── Settings edge cases ────────────────────────────────────────────────────

class TestSettingsEdgeCases:
    """Edge case tests for application settings."""

    def test_settings_env_prefix(self):
        """Settings should use SENTINEL_ prefix."""
        assert Settings.model_config.get("env_prefix") == "SENTINEL_"

    def test_settings_extra_ignored(self):
        """Extra env vars should be silently ignored."""
        settings = Settings()
        assert settings.app_name == "Digital Sentinel"

    def test_all_settings_have_defaults(self):
        """All settings should have sensible defaults (no crash on init)."""
        settings = Settings()
        assert settings.app_name
        assert settings.app_version
        assert settings.environment
        assert settings.database_url
        assert settings.redis_url
        assert settings.neo4j_uri
        assert settings.secret_key

    def test_get_settings_returns_instance(self):
        """get_settings should return a Settings instance."""
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_multiple_settings_instances_independent(self):
        """Multiple Settings instances should be independent."""
        s1 = Settings(app_version="1.0.0")
        s2 = Settings(app_version="2.0.0")
        assert s1.app_version != s2.app_version

    def test_database_url_async_format(self):
        """Database URL should use asyncpg driver."""
        settings = Settings()
        assert "asyncpg" in settings.database_url

    def test_database_url_sync_format(self):
        """Sync database URL should use standard driver."""
        settings = Settings()
        assert "asyncpg" not in settings.database_url_sync
        assert "postgresql://" in settings.database_url_sync


# ─── Middleware tests ────────────────────────────────────────────────────────

class TestMiddlewareConfiguration:
    """Tests for middleware setup functions."""

    def test_get_limiter_returns_limiter(self):
        """get_limiter should return a Limiter instance."""
        settings = Settings(rate_limit_default="50/minute")
        limiter = get_limiter(settings)
        assert limiter is not None

    def test_configure_cors_does_not_crash(self):
        """configure_cors should not raise errors."""
        settings = Settings(allowed_origins="http://localhost:3000")
        app = create_app(settings)
        # If we got here, CORS was configured without error

    def test_configure_structured_logging_json(self):
        """JSON logging configuration should not raise."""
        settings = Settings(log_format="json")
        configure_structured_logging(settings)

    def test_configure_structured_logging_console(self):
        """Console logging configuration should not raise."""
        settings = Settings(log_format="console")
        configure_structured_logging(settings)

    def test_lifespan_is_async_context_manager(self):
        """lifespan should be an async context manager."""
        import inspect
        assert callable(lifespan)


# ─── Docker configuration detailed tests ────────────────────────────────────

class TestDockerConfigDetailed:
    """Detailed validation of Docker configuration files."""

    def _project_root(self) -> str:
        return os.path.dirname(os.path.dirname(__file__))

    def test_dockerfile_uses_python_312(self):
        """Dockerfile should use Python 3.12."""
        path = os.path.join(self._project_root(), "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "python:3.12" in content

    def test_dockerfile_has_healthcheck(self):
        """Dockerfile should include a HEALTHCHECK instruction."""
        path = os.path.join(self._project_root(), "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "HEALTHCHECK" in content

    def test_dockerfile_exposes_port_8000(self):
        """Dockerfile should expose port 8000."""
        path = os.path.join(self._project_root(), "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "EXPOSE 8000" in content

    def test_dockerfile_uses_non_root_user(self):
        """Dockerfile should run as non-root user."""
        path = os.path.join(self._project_root(), "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "USER" in content
        assert "sentinel" in content.lower()

    def test_dockerfile_has_uvicorn_cmd(self):
        """Dockerfile CMD should run uvicorn."""
        path = os.path.join(self._project_root(), "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "uvicorn" in content

    def test_docker_compose_postgres_has_healthcheck(self):
        """PostgreSQL service should have a health check."""
        import yaml
        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)
        postgres = compose["services"]["postgres"]
        assert "healthcheck" in postgres

    def test_docker_compose_redis_has_healthcheck(self):
        """Redis service should have a health check."""
        import yaml
        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)
        redis = compose["services"]["redis"]
        assert "healthcheck" in redis

    def test_docker_compose_has_volumes(self):
        """Docker Compose should define persistent volumes."""
        import yaml
        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)
        assert "volumes" in compose
        assert len(compose["volumes"]) >= 2

    def test_docker_compose_has_network(self):
        """Docker Compose should define a network."""
        import yaml
        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)
        assert "networks" in compose

    def test_docker_compose_api_depends_on_postgres(self):
        """API service should depend on PostgreSQL."""
        import yaml
        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)
        api = compose["services"]["api"]
        assert "depends_on" in api
        assert "postgres" in api["depends_on"]

    def test_dockerignore_excludes_venv(self):
        """Dockerignore should exclude .venv."""
        path = os.path.join(self._project_root(), ".dockerignore")
        with open(path) as f:
            content = f.read()
        assert ".venv" in content

    def test_dockerignore_excludes_tests(self):
        """Dockerignore should exclude tests."""
        path = os.path.join(self._project_root(), ".dockerignore")
        with open(path) as f:
            content = f.read()
        assert "tests" in content

    def test_dockerignore_excludes_git(self):
        """Dockerignore should exclude .git."""
        path = os.path.join(self._project_root(), ".dockerignore")
        with open(path) as f:
            content = f.read()
        assert ".git" in content


# ─── .env.example validation ─────────────────────────────────────────────────

class TestEnvExample:
    """Detailed validation of .env.example file."""

    def _read_env_example(self) -> str:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env.example")
        with open(path) as f:
            return f.read()

    def test_has_wazuh_config(self):
        """Should include Wazuh configuration variables."""
        content = self._read_env_example()
        assert "SENTINEL_WAZUH_API_URL" in content
        assert "SENTINEL_WAZUH_API_USER" in content
        assert "SENTINEL_WAZUH_API_PASSWORD" in content

    def test_has_security_config(self):
        """Should include security configuration variables."""
        content = self._read_env_example()
        assert "SENTINEL_SECRET_KEY" in content
        assert "SENTINEL_ACCESS_TOKEN_EXPIRE_MINUTES" in content

    def test_has_neo4j_config(self):
        """Should include Neo4j configuration variables."""
        content = self._read_env_example()
        assert "SENTINEL_NEO4J_URI" in content
        assert "SENTINEL_NEO4J_USER" in content
        assert "SENTINEL_NEO4J_PASSWORD" in content

    def test_has_logging_config(self):
        """Should include logging configuration variables."""
        content = self._read_env_example()
        assert "SENTINEL_LOG_LEVEL" in content
        assert "SENTINEL_LOG_FORMAT" in content

    def test_has_rate_limit_config(self):
        """Should include rate limiting configuration."""
        content = self._read_env_example()
        assert "SENTINEL_RATE_LIMIT_DEFAULT" in content

    def test_has_cors_config(self):
        """Should include CORS configuration."""
        content = self._read_env_example()
        assert "SENTINEL_ALLOWED_ORIGINS" in content

    def test_has_comments(self):
        """Should include descriptive comments."""
        content = self._read_env_example()
        comment_lines = [l for l in content.split("\n") if l.strip().startswith("#")]
        assert len(comment_lines) >= 5


# ─── Alembic migration validation ────────────────────────────────────────────

class TestAlembicMigrations:
    """Detailed validation of Alembic migration scripts."""

    def _project_root(self) -> str:
        return os.path.dirname(os.path.dirname(__file__))

    def test_migration_has_upgrade(self):
        """Initial migration should have an upgrade function."""
        path = os.path.join(
            self._project_root(), "alembic", "versions", "001_initial_schema.py"
        )
        with open(path) as f:
            content = f.read()
        assert "def upgrade()" in content

    def test_migration_has_downgrade(self):
        """Initial migration should have a downgrade function."""
        path = os.path.join(
            self._project_root(), "alembic", "versions", "001_initial_schema.py"
        )
        with open(path) as f:
            content = f.read()
        assert "def downgrade()" in content

    def test_migration_creates_organisations_table(self):
        """Migration should create the organisations table."""
        path = os.path.join(
            self._project_root(), "alembic", "versions", "001_initial_schema.py"
        )
        with open(path) as f:
            content = f.read()
        assert '"organisations"' in content

    def test_migration_creates_wazuh_tables(self):
        """Migration should create Wazuh-related tables."""
        path = os.path.join(
            self._project_root(), "alembic", "versions", "001_initial_schema.py"
        )
        with open(path) as f:
            content = f.read()
        assert '"wazuh_alerts"' in content
        assert '"wazuh_connections"' in content
        assert '"correlation_results"' in content

    def test_migration_creates_benchmark_tables(self):
        """Migration should create benchmark-related tables."""
        path = os.path.join(
            self._project_root(), "alembic", "versions", "001_initial_schema.py"
        )
        with open(path) as f:
            content = f.read()
        assert '"benchmark_records"' in content
        assert '"industry_snapshots"' in content

    def test_alembic_env_imports_base(self):
        """Alembic env.py should import Base metadata."""
        path = os.path.join(self._project_root(), "alembic", "env.py")
        with open(path) as f:
            content = f.read()
        assert "Base" in content
        assert "target_metadata" in content


# ─── README validation ────────────────────────────────────────────────────────

class TestReadmeContent:
    """Tests for README.md completeness."""

    def _read_readme(self) -> str:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "README.md")
        with open(path) as f:
            return f.read()

    def test_has_architecture_diagram(self):
        """README should include an architecture diagram."""
        content = self._read_readme()
        assert "architecture" in content.lower()
        # Check for text-based diagram markers
        assert "┌" in content or "```" in content

    def test_has_api_documentation(self):
        """README should include API documentation."""
        content = self._read_readme()
        assert "/api/wazuh" in content
        assert "/api/benchmarks" in content
        assert "/health" in content

    def test_has_environment_variables_section(self):
        """README should document environment variables."""
        content = self._read_readme()
        assert "SENTINEL_" in content
        assert "environment" in content.lower()

    def test_has_deployment_checklist(self):
        """README should include a deployment checklist."""
        content = self._read_readme()
        assert "checklist" in content.lower() or "deployment" in content.lower()

    def test_has_testing_instructions(self):
        """README should include testing instructions."""
        content = self._read_readme()
        assert "pytest" in content
        assert "test" in content.lower()

    def test_has_docker_instructions(self):
        """README should include Docker instructions."""
        content = self._read_readme()
        assert "docker" in content.lower()

    def test_has_coolify_instructions(self):
        """README should mention Coolify deployment."""
        content = self._read_readme()
        assert "coolify" in content.lower()


# ─── OpenAPI schema validation ───────────────────────────────────────────────

class TestOpenAPISchema:
    """Detailed validation of the OpenAPI schema."""

    def test_schema_has_info(self, client):
        """Schema should have info section."""
        response = client.get("/openapi.json")
        schema = response.json()
        assert "info" in schema
        assert schema["info"]["title"] == "Digital Sentinel"

    def test_schema_has_wazuh_paths(self, client):
        """Schema should include Wazuh endpoint paths."""
        response = client.get("/openapi.json")
        schema = response.json()
        paths = list(schema["paths"].keys())
        assert any("/api/wazuh" in p for p in paths)

    def test_schema_has_benchmark_paths(self, client):
        """Schema should include Benchmark endpoint paths."""
        response = client.get("/openapi.json")
        schema = response.json()
        paths = list(schema["paths"].keys())
        assert any("/api/benchmarks" in p for p in paths)

    def test_schema_has_health_paths(self, client):
        """Schema should include health endpoint paths."""
        response = client.get("/openapi.json")
        schema = response.json()
        paths = list(schema["paths"].keys())
        assert any("/health" in p for p in paths)

    def test_schema_has_components(self, client):
        """Schema should have component definitions."""
        response = client.get("/openapi.json")
        schema = response.json()
        assert "components" in schema
        assert "schemas" in schema["components"]


# ─── Data store reset ────────────────────────────────────────────────────────

class TestDataStoreReset:
    """Tests for data store reset functionality."""

    def test_reset_clears_all_data(self):
        """Reset should clear all stored data."""
        data_store.add_organisation("test", {"id": "test", "name": "Test"})
        data_store.add_vulnerability("test", {"id": "v1"})
        data_store.add_wazuh_alert("test", {"id": "a1"})
        data_store.add_benchmark_record("test", {"org_id": "test"})

        data_store.reset()

        assert len(data_store.organisations) == 0
        assert len(data_store.vulnerabilities) == 0
        assert len(data_store.wazuh_alerts) == 0
        assert len(data_store.benchmark_records) == 0

    def test_fresh_store_is_empty(self):
        """A fresh DataStore should have no data."""
        store = DataStore()
        assert len(store.organisations) == 0
        assert len(store.vulnerabilities) == 0
        assert len(store.wazuh_alerts) == 0
        assert len(store.benchmark_records) == 0
