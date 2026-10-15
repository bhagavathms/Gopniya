"""Typed runtime configuration.

Every knob is read from the environment (prefix ``GOPNIYA_``) or an optional
``.env`` file, validated once at startup, and then shared as an immutable
singleton. A bad value fails the boot instead of surfacing mid-request.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GOPNIYA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # --- Service -------------------------------------------------------------
    app_name: str = "gopniya"
    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"

    # --- PostgreSQL ----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://gopniya:gopniya@localhost:5432/gopniya"
    db_pool_size: int = Field(default=20, ge=1)
    db_max_overflow: int = Field(default=10, ge=0)
    # Convenient for local dev; in production run migrations (Alembic) instead.
    db_auto_create_schema: bool = True

    # --- Redis ---------------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = Field(default=256, ge=1)
    # Redis sits on the hot path: fail fast rather than queue behind a sick node.
    redis_socket_timeout: float = Field(default=0.25, gt=0)

    # --- Kafka ---------------------------------------------------------------
    kafka_enabled: bool = True
    kafka_bootstrap_servers: str = "localhost:29092"
    kafka_audit_topic: str = "gopniya.audit.v1"
    kafka_linger_ms: int = Field(default=10, ge=0)
    kafka_consumer_group: str = "gopniya-audit-sink"

    # --- Authentication ------------------------------------------------------
    # Seeded into Postgres on startup so a fresh stack is usable immediately.
    bootstrap_api_key: SecretStr | None = None
    bootstrap_tenant: str = "default"
    api_key_cache_ttl_seconds: int = Field(default=60, ge=1)

    # --- Upstream LLM providers (OpenAI-compatible) --------------------------
    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: SecretStr = SecretStr("")
    fallback_base_url: str | None = None
    fallback_api_key: SecretStr | None = None
    fallback_model: str | None = None  # rewrite `model` when failing over
    upstream_connect_timeout: float = Field(default=3.0, gt=0)
    upstream_read_timeout: float = Field(default=120.0, gt=0)
    upstream_max_connections: int = Field(default=512, ge=1)
    upstream_max_keepalive: int = Field(default=128, ge=0)
    upstream_max_retries: int = Field(default=2, ge=0)
    upstream_retry_backoff: float = Field(default=0.2, ge=0)

    # --- Circuit breaker -----------------------------------------------------
    circuit_failure_threshold: int = Field(default=5, ge=1)
    circuit_recovery_seconds: float = Field(default=30.0, gt=0)

    # --- Rate limiting (token bucket, per tenant) ----------------------------
    rate_limit_capacity: int = Field(default=60, ge=1)  # burst size
    rate_limit_refill_per_second: float = Field(default=1.0, gt=0)  # sustained rate
    rate_limit_fail_open: bool = True  # availability over strictness if Redis is down

    # --- Exact-match response cache ------------------------------------------
    cache_enabled: bool = True
    cache_ttl_seconds: int = Field(default=300, ge=1)
    # Only cache requests that asked for deterministic output.
    cache_max_temperature: float = Field(default=0.0, ge=0)

    # --- Guardrails ----------------------------------------------------------
    guardrail_pii_action: Literal["redact", "block", "allow"] = "redact"
    guardrail_block_prompt_injection: bool = True
    guardrail_injection_threshold: float = Field(default=1.0, gt=0)
    guardrail_scan_responses: bool = True
    max_request_chars: int = Field(default=200_000, ge=1)


@lru_cache
def get_settings() -> Settings:
    return Settings()
