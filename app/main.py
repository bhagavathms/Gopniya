"""Gopniya gateway entrypoint.

Request pipeline for ``POST /v1/chat/completions``:

    authenticate -> rate limit -> guardrails (redact / block) -> cache lookup
        -> forward (retry, circuit breaker, fallback) -> response guardrails
        -> cache store -> respond -> audit event to Kafka (off the hot path)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings, get_settings
from app.database import Datastores
from app.models import AuditEvent, ChatCompletionRequest, ErrorDetail, ErrorResponse, HealthResponse, Principal
from app.services import (
    ApiKeyAuthenticator,
    AuditProducer,
    GatewayError,
    GuardrailEngine,
    ResponseCache,
    TokenBucketRateLimiter,
    UpstreamForwarder,
    ensure_bootstrap_key,
)

logger = logging.getLogger("gopniya")


@dataclass(slots=True)
class GatewayContext:
    """Process-wide singletons, built once in the lifespan."""

    settings: Settings
    stores: Datastores
    auth: ApiKeyAuthenticator
    limiter: TokenBucketRateLimiter
    cache: ResponseCache
    guardrails: GuardrailEngine
    forwarder: UpstreamForwarder
    audit: AuditProducer


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    stores = Datastores(settings)
    if settings.db_auto_create_schema:
        await stores.create_schema()
    if settings.bootstrap_api_key:
        await ensure_bootstrap_key(
            stores.session_factory, settings.bootstrap_api_key.get_secret_value(), settings.bootstrap_tenant
        )

    audit = AuditProducer(settings)
    await audit.start()
    forwarder = UpstreamForwarder(settings)

    app.state.ctx = GatewayContext(
        settings=settings,
        stores=stores,
        auth=ApiKeyAuthenticator(stores.redis, stores.session_factory, settings),
        limiter=TokenBucketRateLimiter(stores.redis, settings),
        cache=ResponseCache(stores.redis, settings),
        guardrails=GuardrailEngine(settings),
        forwarder=forwarder,
        audit=audit,
    )
    logger.info("gopniya ready (upstreams=%s)", [u.name for u in forwarder.upstreams])
    try:
        yield
    finally:
        # Reverse order of dependency: stop taking upstream traffic, flush
        # audit events, then release pools.
        await forwarder.close()
        await audit.stop()
        await stores.close()


class RequestIdMiddleware:
    """Pure-ASGI middleware (cheaper than BaseHTTPMiddleware, safe for streaming).

    Honours an inbound ``X-Request-ID`` for end-to-end tracing, otherwise
    mints one, and echoes it on every response.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        inbound = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        request_id = inbound if 0 < len(inbound) <= 64 else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_with_id)


app = FastAPI(
    title="Gopniya",
    description="Enterprise AI gateway and security proxy (OpenAI-compatible).",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(RequestIdMiddleware)


# -----------------------------------------------------------------------------
# Error handling: always the OpenAI error envelope
# -----------------------------------------------------------------------------


def _error(status: int, message: str, error_type: str, code: str | None, headers: dict[str, str] | None = None) -> JSONResponse:
    body = ErrorResponse(error=ErrorDetail(message=message, type=error_type, code=code))
    return JSONResponse(body.model_dump(), status_code=status, headers=headers)


@app.exception_handler(GatewayError)
async def _gateway_error_handler(_: Request, exc: GatewayError) -> JSONResponse:
    return _error(exc.status_code, exc.message, exc.error_type, exc.code, exc.headers)


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    first = exc.errors()[0] if exc.errors() else {}
    location = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
    return _error(400, f"Invalid request: {location} {first.get('msg', '')}".strip(), "invalid_request_error", "invalid_request")


@app.exception_handler(Exception)
async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error request_id=%s", getattr(request.state, "request_id", None))
    return _error(500, "Internal gateway error.", "server_error", "internal_error")


# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------


def get_ctx(request: Request) -> GatewayContext:
    return request.app.state.ctx


async def authenticate(request: Request, ctx: Annotated[GatewayContext, Depends(get_ctx)]) -> Principal:
    return await ctx.auth.authenticate(request.headers.get("authorization"))


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------


@app.get("/healthz", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    """Process is up. Deliberately checks nothing external."""
    return HealthResponse(status="ok", checks={})


@app.get("/readyz", response_model=HealthResponse)
async def readiness(ctx: Annotated[GatewayContext, Depends(get_ctx)]) -> JSONResponse:
    """Ready to serve: Redis and Postgres reachable. Kafka and circuit state are
    reported but don't fail readiness, because the gateway degrades gracefully
    without them."""
    checks: dict[str, Any] = await ctx.stores.health()
    ready = all(checks.values())
    checks["kafka"] = ctx.audit.connected
    checks["circuits"] = ctx.forwarder.circuit_states()
    body = HealthResponse(status="ok" if ready else "degraded", checks=checks)
    return JSONResponse(body.model_dump(), status_code=200 if ready else 503)


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    principal: Annotated[Principal, Depends(authenticate)],
    ctx: Annotated[GatewayContext, Depends(get_ctx)],
) -> Response:
    started = time.perf_counter()
    request_id: str = request.state.request_id
    audit = AuditEvent(
        request_id=request_id,
        tenant_id=principal.tenant_id,
        api_key_id=principal.api_key_id,
        model=body.model,
        stream=body.stream,
        client_ip=request.client.host if request.client else None,
    )
    handed_to_stream = False  # once true, the stream relay owns the audit event

    try:
        # 1. Rate limit (single atomic Redis round-trip).
        decision = await ctx.limiter.acquire(principal)
        headers = decision.headers()
        if not decision.allowed:
            raise GatewayError(429, "Rate limit exceeded.", "rate_limit_error", "rate_limit_exceeded", headers)

        # 2. Guardrails: redact PII/secrets, block injection attempts.
        payload = body.upstream_payload()
        verdict = ctx.guardrails.inspect_request(payload["messages"])
        audit.guardrail_action, audit.guardrail_findings = verdict.action, verdict.findings
        headers["X-Gopniya-Guardrail"] = verdict.action
        if verdict.blocked:
            raise GatewayError(400, verdict.reason or "Request blocked.", "invalid_request_error", "content_policy_violation", headers)
        payload["messages"] = verdict.messages
        audit.prompt_sha256 = hashlib.sha256(
            json.dumps(verdict.messages, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()

        # 3a. Streaming: relay SSE bytes as they arrive.
        if body.stream:
            result = await ctx.forwarder.forward(payload, request_id, stream=True)
            audit.upstream, audit.upstream_latency_ms = result.upstream, result.latency_ms
            audit.status_code = result.response.status_code
            if result.response.status_code >= 400:
                content = await result.response.aread()
                await result.response.aclose()
                return Response(content, result.response.status_code, headers=headers,
                                media_type=result.response.headers.get("content-type", "application/json"))  # fmt: skip
            handed_to_stream = True
            return StreamingResponse(
                _relay_stream(result.response, audit, started, ctx.audit),
                status_code=result.response.status_code,
                media_type="text/event-stream",
                headers={**headers, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        # 3b. Non-streaming: exact-match cache first.
        cache_key: str | None = None
        if ctx.cache.is_cacheable(body):
            cache_key = ctx.cache.key_for(principal.tenant_id, payload)
            if (cached := await ctx.cache.get(cache_key)) is not None:
                audit.cache_hit, audit.status_code = True, 200
                return JSONResponse(cached, headers={**headers, "X-Gopniya-Cache": "HIT"})

        result = await ctx.forwarder.forward(payload, request_id, stream=False)
        audit.upstream, audit.upstream_latency_ms = result.upstream, result.latency_ms
        audit.status_code = result.response.status_code
        try:
            data = result.response.json()
        except ValueError as exc:
            raise GatewayError(502, "Upstream returned a non-JSON response.", "upstream_error", "bad_upstream_response") from exc

        if result.response.status_code < 400 and isinstance(data, dict):
            # 4. Output guardrails: stop PII/secrets leaking back to the caller.
            if out_findings := ctx.guardrails.inspect_response(data):
                audit.guardrail_findings = {
                    **audit.guardrail_findings, **{f"OUTPUT_{k}": v for k, v in out_findings.items()}
                }
            usage = data.get("usage") or {}
            audit.prompt_tokens = usage.get("prompt_tokens")
            audit.completion_tokens = usage.get("completion_tokens")
            audit.total_tokens = usage.get("total_tokens")
            if cache_key:
                await ctx.cache.set(cache_key, data)

        if cache_key:
            headers["X-Gopniya-Cache"] = "MISS"
        return JSONResponse(data, status_code=result.response.status_code, headers=headers)

    except GatewayError as exc:
        audit.status_code, audit.error = exc.status_code, exc.code
        raise
    except Exception:
        audit.status_code, audit.error = 500, "internal_error"
        raise
    finally:
        if not handed_to_stream:
            audit.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            ctx.audit.emit(audit)


async def _relay_stream(
    response: httpx.Response, audit: AuditEvent, started: float, producer: AuditProducer
) -> AsyncIterator[bytes]:
    """Relay upstream SSE chunks unmodified; emit the audit event when done.

    Output guardrails are not applied mid-stream (PII can span chunk
    boundaries and buffering would destroy time-to-first-token); see DESIGN.md.
    """
    try:
        async for chunk in response.aiter_bytes():
            yield chunk
    except httpx.HTTPError:
        # Headers (200) are already sent; signal the failure in-band, in the
        # same shape OpenAI uses for mid-stream errors.
        audit.error = "upstream_stream_interrupted"
        error = ErrorResponse(error=ErrorDetail(message="Upstream stream interrupted.", type="upstream_error"))
        yield f"data: {error.model_dump_json()}\n\n".encode()
    except (asyncio.CancelledError, GeneratorExit):
        # Cancelled while awaiting upstream, or closed while parked at `yield`.
        audit.error = "client_disconnected"
        raise
    finally:
        await response.aclose()
        audit.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        producer.emit(audit)
