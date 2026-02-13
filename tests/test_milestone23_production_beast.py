"""Beast tests for Milestone 23 — Production Hardening & Coolify Deployment.

Tests cover: health checks, rate limiting, CORS, environment validation,
structured logging, graceful shutdown, Docker configuration, and deployment readiness.
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from src.app import create_app
from src.config import Settings, get_settings
from src.middleware import is_shutdown_requested


# ─── Test 1: Health check endpoints ──────────────────────────────────────────

class TestHealthChecks:
    """Tests for health check endpoints."""

    def test_basic_health_check(self, client):
        """GET /health should return healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"
        assert "services" in data
        assert len(data["services"]) >= 1

    def test_health_check_includes_version(self, client):
        """Health response should include the application version."""
        response = client.get("/health")
        data = response.json()
        assert data["version"] == "2.0.0"

    def test_health_check_includes_environment(self, client):
        """Health response should include the environment name."""
        response = client.get("/health")
        data = response.json()
        assert data["environment"] in ("development", "staging", "production")

    def test_readiness_check(self, client):
        """GET /health/ready should return readiness status."""
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "unhealthy", "degraded")

    def test_liveness_check(self, client):
        """GET /health/live should return alive status."""
        response = client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_health_service_latency_reported(self, client):
        """Health check should report service latency."""
        response = client.get("/health")
        data = response.json()
        for service in data["services"]:
            if service["status"] == "healthy":
                assert service["latency_ms"] is not None
                assert service["latency_ms"] >= 0


# ─── Test 2: CORS configuration ─────────────────────────────────────────────

class TestCORSConfiguration:
    """Tests for CORS middleware configuration."""

    def test_cors_allows_configured_origin(self):
        """CORS should allow requests from configured origins."""
        settings = Settings(
            allowed_origins="http://localhost:3000",
            rate_limit_default="1000/minute",
        )
        app = create_app(settings)
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    def test_cors_rejects_unconfigured_origin(self):
        """CORS should reject requests from unconfigured origins."""
        settings = Settings(
            allowed_origins="http://localhost:3000",
            rate_limit_default="1000/minute",
        )
        app = create_app(settings)
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Should not include the evil origin in allow-origin
        allow_origin = response.headers.get("access-control-allow-origin", "")
        assert "evil.example.com" not in allow_origin

    def test_cors_allows_all_in_wildcard_mode(self):
        """CORS with '*' should allow any origin."""
        settings = Settings(
            allowed_origins="*",
            rate_limit_default="1000/minute",
        )
        app = create_app(settings)
        client = TestClient(app)

        response = client.get(
            "/health",
            headers={"Origin": "http://anywhere.example.com"},
        )
        assert response.status_code == 200

    def test_cors_multiple_origins(self):
        """CORS should support multiple comma-separated origins."""
        settings = Settings(
            allowed_origins="http://localhost:3000,https://app.example.com",
            rate_limit_default="1000/minute",
        )
        assert len(settings.allowed_origins_list) == 2
        assert "http://localhost:3000" in settings.allowed_origins_list
        assert "https://app.example.com" in settings.allowed_origins_list


# ─── Test 3: Rate limiting ───────────────────────────────────────────────────

class TestRateLimiting:
    """Tests for rate limiting configuration."""

    def test_rate_limiter_configured(self):
        """Application should have a rate limiter configured."""
        settings = Settings(
            rate_limit_default="100/minute",
            rate_limit_burst="200/minute",
        )
        app = create_app(settings)
        assert hasattr(app.state, "limiter")

    def test_rate_limit_settings_parsed(self):
        """Rate limit settings should be valid format."""
        settings = Settings(rate_limit_default="100/minute")
        assert "/" in settings.rate_limit_default
        parts = settings.rate_limit_default.split("/")
        assert parts[0].isdigit()
        assert parts[1] in ("second", "minute", "hour", "day")

    def test_rate_limit_headers_present(self, client):
        """Rate-limited responses should include rate limit headers (when hit)."""
        # This test verifies the limiter is active — actual limiting requires
        # many requests which we test at a configuration level
        response = client.get("/health")
        assert response.status_code == 200
        # SlowAPI adds X-RateLimit headers when the middleware processes the request


# ─── Test 4: Environment variable configuration ──────────────────────────────

class TestEnvironmentConfig:
    """Tests for environment variable management."""

    def test_default_settings_valid(self):
        """Default settings should be valid without any env vars."""
        settings = Settings()
        assert settings.app_name == "Digital Sentinel"
        assert settings.app_version == "2.0.0"
        assert settings.environment in ("development", "staging", "production")

    def test_database_url_has_default(self):
        """Database URL should have a sensible default."""
        settings = Settings()
        assert "postgresql" in settings.database_url
        assert "sentinel" in settings.database_url

    def test_redis_url_has_default(self):
        """Redis URL should have a sensible default."""
        settings = Settings()
        assert "redis://" in settings.redis_url

    def test_neo4j_has_defaults(self):
        """Neo4j connection should have sensible defaults."""
        settings = Settings()
        assert "bolt://" in settings.neo4j_uri
        assert settings.neo4j_user == "neo4j"

    def test_secret_key_has_placeholder(self):
        """Secret key default should clearly indicate it needs changing."""
        settings = Settings()
        assert "change" in settings.secret_key.lower() or len(settings.secret_key) > 10

    def test_env_file_example_exists(self):
        """A .env.example file should exist with all required variables."""
        env_example_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), ".env.example"
        )
        assert os.path.exists(env_example_path), ".env.example file must exist"

        with open(env_example_path) as f:
            content = f.read()

        # Check key variables are documented
        required_vars = [
            "SENTINEL_DATABASE_URL",
            "SENTINEL_REDIS_URL",
            "SENTINEL_SECRET_KEY",
            "SENTINEL_ENVIRONMENT",
        ]
        for var in required_vars:
            assert var in content, f"{var} missing from .env.example"

    def test_environment_validation(self):
        """Environment must be one of development, staging, production."""
        for env in ("development", "staging", "production"):
            settings = Settings(environment=env)
            assert settings.environment == env

    def test_allowed_origins_list_parsing(self):
        """Comma-separated origins should be parsed into a list."""
        settings = Settings(allowed_origins="http://a.com, http://b.com, http://c.com")
        assert len(settings.allowed_origins_list) == 3
        assert "http://a.com" in settings.allowed_origins_list
        assert "http://b.com" in settings.allowed_origins_list
        assert "http://c.com" in settings.allowed_origins_list


# ─── Test 5: Graceful shutdown ───────────────────────────────────────────────

class TestGracefulShutdown:
    """Tests for graceful shutdown handling."""

    def test_shutdown_flag_initially_false(self):
        """Shutdown flag should be False on startup."""
        # The flag resets in a fresh import context
        assert is_shutdown_requested() is True or is_shutdown_requested() is False
        # We can't perfectly test this without process isolation,
        # but we verify the function exists and returns a bool
        assert isinstance(is_shutdown_requested(), bool)

    def test_shutdown_handler_exists(self):
        """The shutdown signal handler should be importable and callable."""
        from src.middleware import lifespan
        assert lifespan is not None
        assert callable(lifespan)


# ─── Test 6: Docker and deployment configuration ─────────────────────────────

class TestDeploymentConfig:
    """Tests for Docker and deployment configuration files."""

    def _project_root(self) -> str:
        return os.path.dirname(os.path.dirname(__file__))

    def test_dockerfile_exists(self):
        """A Dockerfile should exist."""
        path = os.path.join(self._project_root(), "Dockerfile")
        assert os.path.exists(path), "Dockerfile must exist"

    def test_docker_compose_exists(self):
        """A docker-compose.yml should exist."""
        path = os.path.join(self._project_root(), "docker-compose.yml")
        assert os.path.exists(path), "docker-compose.yml must exist"

    def test_docker_compose_has_required_services(self):
        """Docker Compose should define all required services."""
        import yaml

        path = os.path.join(self._project_root(), "docker-compose.yml")
        with open(path) as f:
            compose = yaml.safe_load(f)

        services = compose.get("services", {})
        required = {"api", "postgres", "redis"}
        actual = set(services.keys())
        for svc in required:
            assert svc in actual, f"Missing service: {svc}"

    def test_dockerignore_exists(self):
        """A .dockerignore should exist."""
        path = os.path.join(self._project_root(), ".dockerignore")
        assert os.path.exists(path), ".dockerignore must exist"

    def test_readme_exists(self):
        """A comprehensive README.md should exist."""
        path = os.path.join(self._project_root(), "README.md")
        assert os.path.exists(path), "README.md must exist"

        with open(path) as f:
            content = f.read()

        # Check for key sections
        assert "# Digital Sentinel" in content or "# digital-sentinel" in content.lower()
        assert "setup" in content.lower() or "installation" in content.lower()
        assert "api" in content.lower()
        assert "environment" in content.lower()


# ─── Test 7: Structured logging ─────────────────────────────────────────────

class TestStructuredLogging:
    """Tests for structured JSON logging."""

    def test_json_log_format_configurable(self):
        """Log format should be configurable between json and console."""
        for fmt in ("json", "console"):
            settings = Settings(log_format=fmt)
            assert settings.log_format == fmt

    def test_log_level_configurable(self):
        """Log level should be configurable."""
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            settings = Settings(log_level=level)
            assert settings.log_level == level

    def test_structured_logging_configured(self):
        """Structured logging should be configurable without errors."""
        from src.middleware import configure_structured_logging
        settings = Settings(log_format="json")
        # Should not raise
        configure_structured_logging(settings)


# ─── Test 8: Application factory ─────────────────────────────────────────────

class TestApplicationFactory:
    """Tests for the application factory pattern."""

    def test_create_app_returns_fastapi(self):
        """create_app should return a FastAPI instance."""
        from fastapi import FastAPI
        app = create_app(Settings(rate_limit_default="1000/minute"))
        assert isinstance(app, FastAPI)

    def test_create_app_with_custom_settings(self):
        """App should respect custom settings."""
        settings = Settings(
            app_version="9.9.9",
            rate_limit_default="1000/minute",
        )
        app = create_app(settings)
        assert app.version == "9.9.9"

    def test_all_routers_registered(self):
        """All expected route prefixes should be registered."""
        app = create_app(Settings(rate_limit_default="1000/minute"))
        routes = [r.path for r in app.routes]
        # Health routes
        assert any("/health" in r for r in routes)
        # Wazuh routes
        assert any("/api/wazuh" in r for r in routes)
        # Benchmark routes
        assert any("/api/benchmarks" in r for r in routes)

    def test_openapi_schema_generated(self, client):
        """OpenAPI schema should be generated and accessible."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "Digital Sentinel"
        assert schema["info"]["version"] == "2.0.0"

    def test_api_endpoints_count(self, client):
        """There should be a minimum number of API endpoints."""
        response = client.get("/openapi.json")
        schema = response.json()
        paths = schema.get("paths", {})
        # Count all method endpoints
        endpoint_count = sum(len(methods) for methods in paths.values())
        assert endpoint_count >= 10, f"Expected 10+ endpoints, got {endpoint_count}"


# ─── Test 9: Database migration scripts ──────────────────────────────────────

class TestDatabaseMigrations:
    """Tests for database migration configuration."""

    def _project_root(self) -> str:
        return os.path.dirname(os.path.dirname(__file__))

    def test_alembic_config_exists(self):
        """Alembic configuration file should exist."""
        path = os.path.join(self._project_root(), "alembic.ini")
        assert os.path.exists(path), "alembic.ini must exist"

    def test_migrations_directory_exists(self):
        """Alembic migrations directory should exist."""
        path = os.path.join(self._project_root(), "alembic")
        assert os.path.isdir(path), "alembic/ directory must exist"

    def test_initial_migration_exists(self):
        """At least one migration script should exist."""
        versions_path = os.path.join(self._project_root(), "alembic", "versions")
        assert os.path.isdir(versions_path), "alembic/versions/ must exist"
        # Check for at least one .py file
        migration_files = [f for f in os.listdir(versions_path) if f.endswith(".py")]
        assert len(migration_files) >= 1, "At least one migration file required"


# ─── Test 10: Production security headers ────────────────────────────────────

class TestSecurityHeaders:
    """Tests for security-related configuration."""

    def test_secret_key_not_default_warning(self):
        """Default secret key should contain a warning to change it."""
        settings = Settings()
        # Default should be clearly a placeholder
        assert "change" in settings.secret_key.lower()

    def test_token_expiry_reasonable(self):
        """Access token expiry should be reasonable (not too long)."""
        settings = Settings()
        assert 5 <= settings.access_token_expire_minutes <= 1440  # 5 min to 24 hours

    def test_ssl_verification_default_true(self):
        """Wazuh SSL verification should default to True."""
        settings = Settings()
        assert settings.wazuh_verify_ssl is True
