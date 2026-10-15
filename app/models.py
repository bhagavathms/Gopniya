"""Persistence models (SQLAlchemy 2.0) and wire schemas (Pydantic v2).

Both live together on purpose: the audit event schema published to Kafka maps
1:1 onto the ``audit_logs`` table, and keeping them side by side makes drift
obvious in review.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import BigInteger, Boolean, DateTime, Float, Index, Integer, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# =============================================================================
# ORM
# =============================================================================


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    """A gateway credential. Only the SHA-256 digest of the key is stored."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12))  # for humans identifying a key
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    # NULL means "use the gateway default from Settings".
    rate_limit_capacity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_refill_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """One row per proxied request, written by the Kafka audit sink.

    Raw prompts and completions are deliberately never persisted; only a
    digest of the (already redacted) prompt and guardrail finding counts.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), unique=True)  # idempotency key
    tenant_id: Mapped[str] = mapped_column(String(64))
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model: Mapped[str] = mapped_column(String(128))
    upstream: Mapped[str | None] = mapped_column(String(32), nullable=True)
    stream: Mapped[bool] = mapped_column(Boolean, default=False)
    status_code: Mapped[int] = mapped_column(Integer)
    latency_ms: Mapped[float] = mapped_column(Float)
    upstream_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    guardrail_action: Mapped[str] = mapped_column(String(16), default="allow")
    guardrail_findings: Mapped[dict[str, int]] = mapped_column(JSONB, default=dict)
    prompt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# =============================================================================
# API schemas (OpenAI-compatible surface)
# =============================================================================


class ChatMessage(BaseModel):
    # extra="allow": tool_calls, tool_call_id, etc. pass through untouched.
    model_config = ConfigDict(extra="allow")

    role: Literal["system", "developer", "user", "assistant", "tool", "function"]
    content: str | list[dict[str, Any]] | None = None
    name: str | None = None


class ChatCompletionRequest(BaseModel):
    """Validates the fields the gateway acts on; forwards everything else verbatim."""

    model_config = ConfigDict(extra="allow")

    model: str = Field(min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1, max_length=2048)
    stream: bool = False
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, gt=0)
    user: str | None = None

    def upstream_payload(self) -> dict[str, Any]:
        # exclude_unset keeps the request byte-for-byte faithful to what the
        # client sent instead of injecting defaults the provider never saw.
        return self.model_dump(exclude_unset=True)


class ErrorDetail(BaseModel):
    message: str
    type: str
    code: str | None = None


class ErrorResponse(BaseModel):
    """Same envelope as OpenAI so existing SDKs surface gateway errors cleanly."""

    error: ErrorDetail


class Principal(BaseModel):
    """The authenticated caller, cached in Redis after the first DB lookup."""

    api_key_id: str
    tenant_id: str
    rate_limit_capacity: int
    rate_limit_refill_per_second: float


class AuditEvent(BaseModel):
    """Kafka message schema (topic ``gopniya.audit.v1``); mirrors ``AuditLog``."""

    request_id: str
    tenant_id: str
    api_key_id: str | None = None
    model: str
    upstream: str | None = None
    stream: bool = False
    status_code: int = 0
    latency_ms: float = 0.0
    upstream_latency_ms: float | None = None
    cache_hit: bool = False
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    guardrail_action: str = "allow"
    guardrail_findings: dict[str, int] = Field(default_factory=dict)
    prompt_sha256: str | None = None
    client_ip: str | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, Any]
