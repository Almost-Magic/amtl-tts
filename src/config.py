"""Application configuration via environment variables."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration for Digital Sentinel."""

    # Application
    app_name: str = "Digital Sentinel"
    app_version: str = "2.0.0"
    debug: bool = False
    environment: str = Field(default="development", pattern=r"^(development|staging|production)$")
    log_level: str = "INFO"
    log_format: str = "json"

    # API
    api_prefix: str = "/api"
    allowed_origins: str = "http://localhost:3000"
    rate_limit_default: str = "100/minute"
    rate_limit_burst: str = "200/minute"

    # PostgreSQL / TimescaleDB
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    database_url_sync: str = "postgresql://sentinel:sentinel@localhost:5432/sentinel"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "sentinel"

    # Wazuh
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_verify_ssl: bool = True

    # Security
    secret_key: str = "change-me-in-production-please"
    access_token_expire_minutes: int = 30

    # External services
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    openai_api_key: str = ""

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    model_config = {"env_prefix": "SENTINEL_", "env_file": ".env", "extra": "ignore"}


def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
