"""Gopniya business logic, consolidated.

Sections:
    1. Errors            - GatewayError, rendered as OpenAI-style error JSON
    2. Authentication    - API-key lookup (Postgres) with a Redis read-through cache
    3. Rate limiting     - distributed token bucket, one atomic Lua call per request
    4. Response cache    - tenant-scoped exact-match cache for deterministic requests
    5. Guardrails        - regex/heuristic PII + secret redaction, prompt-injection scoring
    6. Upstream proxy    - pooled httpx client, retries, circuit breakers, fallback
    7. Audit pipeline    - fire-and-forget Kafka producer + Kafka->Postgres sink worker

Run the audit sink with:  python -m app.services
"""

from __future__ import annotations

import asyncio
import email.utils
import hashlib
import json
import logging
import random
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError
from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.models import ApiKey, AuditEvent, AuditLog, ChatCompletionRequest, Principal

logger = logging.getLogger("gopniya")


# =============================================================================
# 1. Errors
# =============================================================================


class GatewayError(Exception):
    """An error the gateway reports to the client with a specific status."""

    def __init__(
        self,
        status_code: int,
        message: str,
        error_type: str,
        code: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.error_type = error_type
        self.code = code
        self.headers = headers or {}


# =============================================================================
# 2. Authentication
# =============================================================================

_NEGATIVE_CACHE_MARKER = "-"
_NEGATIVE_CACHE_TTL = 10


def hash_api_key(raw_key: str) -> str:
    # Keys are high-entropy random tokens, so a fast unsalted digest is safe and
    # keeps lookup O(1); slow KDFs (bcrypt/argon2) only matter for low-entropy
    # human passwords and would add milliseconds to every request.
    return hashlib.sha256(raw_key.encode()).hexdigest()


class ApiKeyAuthenticator:
    def __init__(
        self,
        redis: Redis,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._redis = redis
        self._sessions = session_factory
        self._settings = settings

    async def authenticate(self, authorization: str | None) -> Principal:
        if not authorization or not authorization[:7].lower() == "bearer ":
            raise GatewayError(401, "Missing bearer token.", "authentication_error", "missing_api_key")
        raw_key = authorization[7:].strip()
        if not raw_key:
            raise GatewayError(401, "Missing bearer token.", "authentication_error", "missing_api_key")

        digest = hash_api_key(raw_key)
        cache_key = f"gopniya:auth:{digest}"
        try:
            cached = await self._redis.get(cache_key)
        except RedisError:
            cached = None  # degrade to a DB lookup
        if cached == _NEGATIVE_CACHE_MARKER:
            raise GatewayError(401, "Invalid API key.", "authentication_error", "invalid_api_key")
        if cached:
            return Principal.model_validate_json(cached)

        async with self._sessions() as session:
            row = await session.scalar(
                select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.is_active.is_(True))
            )

        if row is None:
            # Negative caching stops a flood of bad keys from hammering Postgres.
            await self._cache_set(cache_key, _NEGATIVE_CACHE_MARKER, _NEGATIVE_CACHE_TTL)
            raise GatewayError(401, "Invalid API key.", "authentication_error", "invalid_api_key")

        principal = Principal(
            api_key_id=str(row.id),
            tenant_id=row.tenant_id,
            rate_limit_capacity=row.rate_limit_capacity or self._settings.rate_limit_capacity,
            rate_limit_refill_per_second=(
                row.rate_limit_refill_per_second or self._settings.rate_limit_refill_per_second
            ),
        )
        await self._cache_set(
            cache_key, principal.model_dump_json(), self._settings.api_key_cache_ttl_seconds
        )
        return principal

    async def _cache_set(self, key: str, value: str, ttl: int) -> None:
        try:
            await self._redis.set(key, value, ex=ttl)
        except RedisError:
            logger.warning("auth cache write failed", exc_info=True)


async def ensure_bootstrap_key(
    session_factory: async_sessionmaker[AsyncSession], raw_key: str, tenant_id: str
) -> None:
    """Idempotently seed one API key so a fresh deployment is usable."""
    stmt = (
        pg_insert(ApiKey)
        .values(
            key_hash=hash_api_key(raw_key),
            key_prefix=raw_key[:8],
            tenant_id=tenant_id,
            name="bootstrap",
            is_active=True,
        )
        .on_conflict_do_nothing(index_elements=["key_hash"])
    )
    async with session_factory() as session:
        await session.execute(stmt)
        await session.commit()


# =============================================================================
# 3. Rate limiting - distributed token bucket
# =============================================================================

# Executed atomically inside Redis: read-refill-consume-write happens with no
# interleaving, so N gateway replicas share one exact bucket per tenant.
# Time comes from Redis itself (TIME), not the caller, so clock skew between
# gateway hosts cannot mint or destroy tokens.
_TOKEN_BUCKET_LUA = """
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local cost     = tonumber(ARGV[3])

local t   = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000

local state  = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

tokens = math.min(capacity, tokens + math.max(0, now - ts) * refill)

local allowed = 0
local retry_after = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after = (cost - tokens) / refill
end

redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
-- Idle buckets expire once they would have refilled completely anyway.
redis.call('EXPIRE', key, math.ceil(capacity / refill) + 1)
-- Lua numbers become integers in replies; return strings to keep fractions.
return {allowed, tostring(tokens), tostring(retry_after)}
"""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: float
    retry_after: float

    def headers(self) -> dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(int(self.remaining)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(max(1, int(self.retry_after + 0.999)))
        return headers


class TokenBucketRateLimiter:
    def __init__(self, redis: Redis, settings: Settings) -> None:
        self._script = redis.register_script(_TOKEN_BUCKET_LUA)  # EVALSHA w/ NOSCRIPT fallback
        self._fail_open = settings.rate_limit_fail_open

    async def acquire(self, principal: Principal, cost: int = 1) -> RateLimitDecision:
        capacity = principal.rate_limit_capacity
        try:
            allowed, remaining, retry_after = await self._script(
                keys=[f"gopniya:rl:{principal.tenant_id}"],
                args=[capacity, principal.rate_limit_refill_per_second, cost],
            )
        except RedisError as exc:
            if self._fail_open:
                logger.warning("rate limiter unavailable; failing open", exc_info=True)
                return RateLimitDecision(True, capacity, capacity, 0.0)
            raise GatewayError(
                503, "Rate limiter unavailable.", "service_unavailable", "rate_limiter_down"
            ) from exc
        return RateLimitDecision(bool(int(allowed)), capacity, float(remaining), float(retry_after))


# =============================================================================
# 4. Response cache - exact match, tenant scoped
# =============================================================================


class ResponseCache:
    """Caches complete non-streaming responses for deterministic requests.

    Keys include the tenant id so one tenant can never read another's
    completions, and are computed from the *redacted* payload so raw PII never
    becomes part of a Redis key.
    """

    def __init__(self, redis: Redis, settings: Settings) -> None:
        self._redis = redis
        self._enabled = settings.cache_enabled
        self._ttl = settings.cache_ttl_seconds
        self._max_temperature = settings.cache_max_temperature

    def is_cacheable(self, request: ChatCompletionRequest) -> bool:
        return (
            self._enabled
            and not request.stream
            and request.temperature is not None
            and request.temperature <= self._max_temperature
        )

    @staticmethod
    def key_for(tenant_id: str, payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return f"gopniya:cache:{tenant_id}:{hashlib.sha256(canonical.encode()).hexdigest()}"

    async def get(self, key: str) -> dict[str, Any] | None:
        try:
            raw = await self._redis.get(key)
        except RedisError:
            logger.warning("cache read failed", exc_info=True)
            return None
        return json.loads(raw) if raw else None

    async def set(self, key: str, body: dict[str, Any]) -> None:
        try:
            await self._redis.set(key, json.dumps(body, separators=(",", ":")), ex=self._ttl)
        except RedisError:
            logger.warning("cache write failed", exc_info=True)


# =============================================================================
# 5. Guardrails - synchronous regex + heuristics
# =============================================================================


def _luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        checksum += d
    return checksum % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)  # fmt: skip
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)  # fmt: skip


def _verhoeff_valid(candidate: str) -> bool:
    """Aadhaar numbers carry a Verhoeff check digit; this kills most false positives."""
    check = 0
    for i, ch in enumerate(reversed([c for c in candidate if c.isdigit()])):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


@dataclass(frozen=True, slots=True)
class _Detector:
    category: str
    kind: Literal["secret", "pii"]
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


# Order matters: each detector runs on the output of the previous one, so
# specific, checksum-validated patterns run before broad ones (cards before
# phone numbers). Every quantifier is bounded to rule out catastrophic
# backtracking (ReDoS) on attacker-controlled prompts.
_DETECTORS: tuple[_Detector, ...] = (
    _Detector("PRIVATE_KEY", "secret", re.compile(
        r"-----BEGIN (?:[A-Z]+ ){0,3}PRIVATE KEY-----[\s\S]{1,16384}?-----END (?:[A-Z]+ ){0,3}PRIVATE KEY-----")),
    _Detector("AWS_ACCESS_KEY", "secret", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Detector("API_KEY", "secret", re.compile(r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,200}|gh[pousr]_[A-Za-z0-9]{36,255}|xox[abprs]-[A-Za-z0-9-]{10,200})\b")),
    _Detector("JWT", "secret", re.compile(r"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,2048}\b")),
    _Detector("EMAIL", "pii", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b")),
    _Detector("CREDIT_CARD", "pii", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _luhn_valid),
    _Detector("AADHAAR", "pii", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), _verhoeff_valid),
    _Detector("SSN", "pii", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    _Detector("PAN", "pii", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")),
    _Detector("PHONE", "pii", re.compile(r"(?<![\w+])\+?\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}(?!\w)")),
    _Detector("IP_ADDRESS", "pii", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
)  # fmt: skip

# (pattern, weight). Scores add up; at or above the threshold the request is
# blocked. These target the classic direct-injection phrasings and role-token
# smuggling; they are a cheap first line, not a complete defence.
_INJECTION_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = tuple(
    (re.compile(p, re.IGNORECASE), w)
    for p, w in (
        (r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|system|your)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules|directives|guidelines)\b", 1.0),
        (r"\b(?:reveal|print|show|repeat|output|leak|dump)\b[^.\n]{0,30}\b(?:system prompt|hidden prompt|initial instructions|developer message|system message)\b", 1.0),
        (r"\byou are now\b[^.\n]{0,40}\b(?:DAN|jailbroken|unfiltered|unrestricted|uncensored|in developer mode)\b", 1.0),
        (r"\b(?:do anything now|developer mode enabled|jailbreak(?:ed)?)\b", 0.6),
        (r"\b(?:pretend|act as if|imagine)\b[^.\n]{0,40}\b(?:no|without)\b[^.\n]{0,20}\b(?:restrictions|rules|guidelines|filters|limits)\b", 0.6),
        (r"<\|im_(?:start|end)\|>|\[/?INST\]|</?\s*system\s*>", 0.5),
    )
)  # fmt: skip

# System/developer prompts are written by the integrating application, not
# the end user, so injection scoring skips them.
_UNTRUSTED_ROLES = frozenset({"user", "tool", "function", "assistant"})


@dataclass(slots=True)
class GuardrailVerdict:
    messages: list[dict[str, Any]]
    action: Literal["allow", "redact", "block"] = "allow"
    findings: dict[str, int] = field(default_factory=dict)
    injection_score: float = 0.0
    reason: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == "block"


class GuardrailEngine:
    """Inline, CPU-bound inspection designed to cost well under a millisecond
    for typical prompts. Heavier ML classifiers belong off the hot path (see
    DESIGN.md)."""

    def __init__(self, settings: Settings) -> None:
        self._pii_action = settings.guardrail_pii_action
        self._block_injection = settings.guardrail_block_prompt_injection
        self._injection_threshold = settings.guardrail_injection_threshold
        self._scan_responses = settings.guardrail_scan_responses
        self._max_chars = settings.max_request_chars

    # -- public API -----------------------------------------------------------

    def inspect_request(self, messages: list[dict[str, Any]]) -> GuardrailVerdict:
        """Return redacted copies of ``messages`` plus a verdict. Never mutates input."""
        if sum(len(text) for _, text in self._iter_text(messages)) > self._max_chars:
            raise GatewayError(
                413, f"Prompt exceeds {self._max_chars} characters.", "invalid_request_error", "prompt_too_large"
            )

        counts: Counter[str] = Counter()
        injection_score = 0.0
        redacted_messages: list[dict[str, Any]] = []

        for message in messages:
            role = message.get("role")
            if role in _UNTRUSTED_ROLES:
                for _, text in self._iter_text([message]):
                    injection_score += self._injection_score(text)
            redacted_messages.append(self._rewrite_message(message, counts))

        verdict = GuardrailVerdict(
            messages=redacted_messages, findings=dict(counts), injection_score=round(injection_score, 2)
        )
        if self._block_injection and injection_score >= self._injection_threshold:
            verdict.findings["PROMPT_INJECTION"] = 1
            verdict.action, verdict.reason = "block", "Request blocked: possible prompt injection."
        elif self._pii_action == "block" and any(k in counts for k in self._pii_categories()):
            verdict.action, verdict.reason = "block", "Request blocked: contains personal data."
        elif self._was_rewritten(counts):
            verdict.action = "redact"
        return verdict

    def inspect_response(self, body: dict[str, Any]) -> dict[str, int]:
        """Redact PII/secrets leaking back out of the model, in place."""
        if not self._scan_responses:
            return {}
        counts: Counter[str] = Counter()
        for choice in body.get("choices") or []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if isinstance(message, dict):
                choice["message"] = self._rewrite_message(message, counts)
        return dict(counts)

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _pii_categories() -> set[str]:
        return {d.category for d in _DETECTORS if d.kind == "pii"}

    def _was_rewritten(self, counts: Counter[str]) -> bool:
        if self._pii_action == "allow":
            return any(d.kind == "secret" and d.category in counts for d in _DETECTORS)
        return bool(counts)

    @staticmethod
    def _iter_text(messages: list[dict[str, Any]]) -> Any:
        """Yield (message_index, text) for plain-string and multi-part content."""
        for i, message in enumerate(messages):
            content = message.get("content")
            if isinstance(content, str):
                yield i, content
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        yield i, part["text"]

    def _rewrite_message(self, message: dict[str, Any], counts: Counter[str]) -> dict[str, Any]:
        content = message.get("content")
        if isinstance(content, str):
            return {**message, "content": self._redact(content, counts)}
        if isinstance(content, list):
            parts = [
                {**part, "text": self._redact(part["text"], counts)}
                if isinstance(part, dict) and isinstance(part.get("text"), str)
                else part
                for part in content
            ]
            return {**message, "content": parts}
        return dict(message)

    def _redact(self, text: str, counts: Counter[str]) -> str:
        for detector in _DETECTORS:
            # Secrets are always scrubbed: forwarding live credentials to a
            # third-party model is never acceptable, whatever the PII policy.
            keep_original = detector.kind == "pii" and self._pii_action == "allow"

            def _sub(match: re.Match[str], d: _Detector = detector, keep: bool = keep_original) -> str:
                value = match.group(0)
                if d.validator is not None and not d.validator(value):
                    return value
                counts[d.category] += 1
                return value if keep else f"[REDACTED_{d.category}]"

            text = detector.pattern.sub(_sub, text)
        return text

    @staticmethod
    def _injection_score(text: str) -> float:
        return sum(weight for pattern, weight in _INJECTION_SIGNALS if pattern.search(text))


# =============================================================================
# 6. Upstream proxy - retries, circuit breaking, fallback
# =============================================================================

# 429/5xx usually mean the request was not processed, so a retry is unlikely
# to double-bill. Read timeouts are *not* retried on the same upstream: the
# model may have generated (and charged for) the completion already.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_RETRYABLE_TRANSPORT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError)


class CircuitBreaker:
    """Classic closed -> open -> half-open breaker, one per upstream per process.

    asyncio is single-threaded, so state changes need no locking.
    """

    def __init__(self, name: str, failure_threshold: int, recovery_seconds: float) -> None:
        self.name = name
        self.state: Literal["closed", "open", "half_open"] = "closed"
        self._threshold = failure_threshold
        self._recovery = recovery_seconds
        self._failures = 0
        self._opened_at = 0.0
        self._probe_started = 0.0

    def allow_request(self) -> bool:
        now = time.monotonic()
        if self.state == "closed":
            return True
        if self.state == "open" and now - self._opened_at >= self._recovery:
            self.state, self._probe_started = "half_open", now
            return True  # this caller is the single probe
        # Half-open: allow a fresh probe only if the previous one vanished
        # (e.g. the client disconnected before we could record its outcome).
        if self.state == "half_open" and now - self._probe_started >= self._recovery:
            self._probe_started = now
            return True
        return False

    def record_success(self) -> None:
        if self.state != "closed":
            logger.info("circuit %s closed", self.name)
        self.state, self._failures = "closed", 0

    def record_failure(self) -> None:
        self._failures += 1
        if self.state == "half_open" or self._failures >= self._threshold:
            if self.state != "open":
                logger.warning("circuit %s opened after %d failures", self.name, self._failures)
            self.state, self._opened_at = "open", time.monotonic()


@dataclass(slots=True)
class Upstream:
    name: str
    base_url: str
    api_key: str
    breaker: CircuitBreaker
    model_override: str | None = None


@dataclass(slots=True)
class UpstreamResponse:
    upstream: str
    response: httpx.Response  # open stream if requested with stream=True
    latency_ms: float  # time to response headers


class UpstreamForwarder:
    def __init__(self, settings: Settings) -> None:
        self._client = httpx.AsyncClient(
            http2=True,  # multiplex many concurrent completions over few sockets
            timeout=httpx.Timeout(
                connect=settings.upstream_connect_timeout,
                read=settings.upstream_read_timeout,
                write=10.0,
                pool=2.0,  # waiting for a pooled connection = overload signal
            ),
            limits=httpx.Limits(
                max_connections=settings.upstream_max_connections,
                max_keepalive_connections=settings.upstream_max_keepalive,
                keepalive_expiry=30.0,
            ),
        )
        self._max_retries = settings.upstream_max_retries
        self._backoff_base = settings.upstream_retry_backoff

        def breaker(name: str) -> CircuitBreaker:
            return CircuitBreaker(name, settings.circuit_failure_threshold, settings.circuit_recovery_seconds)

        self.upstreams: list[Upstream] = [
            Upstream("primary", settings.upstream_base_url.rstrip("/"),
                     settings.upstream_api_key.get_secret_value(), breaker("primary")),
        ]  # fmt: skip
        if settings.fallback_base_url:
            self.upstreams.append(
                Upstream(
                    "fallback",
                    settings.fallback_base_url.rstrip("/"),
                    settings.fallback_api_key.get_secret_value() if settings.fallback_api_key else "",
                    breaker("fallback"),
                    model_override=settings.fallback_model,
                )
            )

    async def close(self) -> None:
        await self._client.aclose()

    def circuit_states(self) -> dict[str, str]:
        return {u.name: u.breaker.state for u in self.upstreams}

    async def forward(self, payload: dict[str, Any], request_id: str, *, stream: bool) -> UpstreamResponse:
        """Send to the first healthy upstream, retrying and failing over.

        Returns non-retryable responses (2xx and client 4xx) as-is. When
        ``stream`` is set the body is left unread so the caller can relay it.
        Fallback is only possible before the first byte reaches the client,
        which is always true here because nothing is relayed until we return.
        """
        failures: list[str] = []
        for upstream in self.upstreams:
            if not upstream.breaker.allow_request():
                failures.append(f"{upstream.name}: circuit open")
                continue

            for attempt in range(self._max_retries + 1):
                retry_after: float | None = None
                started = time.perf_counter()
                try:
                    response = await self._client.send(
                        self._build_request(upstream, payload, request_id), stream=stream
                    )
                except _RETRYABLE_TRANSPORT as exc:
                    upstream.breaker.record_failure()
                    failures.append(f"{upstream.name}: {type(exc).__name__}")
                except httpx.HTTPError as exc:  # read timeout etc.: don't retry here
                    upstream.breaker.record_failure()
                    failures.append(f"{upstream.name}: {type(exc).__name__}")
                    break
                else:
                    latency_ms = (time.perf_counter() - started) * 1000
                    if response.status_code not in _RETRYABLE_STATUS:
                        upstream.breaker.record_success()  # 4xx is the caller's fault
                        return UpstreamResponse(upstream.name, response, latency_ms)
                    upstream.breaker.record_failure()
                    failures.append(f"{upstream.name}: HTTP {response.status_code}")
                    retry_after = _parse_retry_after(response.headers.get("retry-after"))
                    await response.aclose()

                if upstream.breaker.state == "open" or attempt == self._max_retries:
                    break
                await asyncio.sleep(self._backoff(attempt, retry_after))

        logger.error("all upstreams failed request_id=%s failures=%s", request_id, failures)
        all_open = all(u.breaker.state == "open" for u in self.upstreams)
        raise GatewayError(
            503 if all_open else 502,
            "Upstream model provider unavailable.",
            "upstream_error",
            "circuit_open" if all_open else "upstream_failed",
        )

    def _build_request(self, upstream: Upstream, payload: dict[str, Any], request_id: str) -> httpx.Request:
        body = {**payload, "model": upstream.model_override} if upstream.model_override else payload
        return self._client.build_request(
            "POST",
            f"{upstream.base_url}/chat/completions",
            json=body,
            headers={"Authorization": f"Bearer {upstream.api_key}", "X-Request-ID": request_id},
        )

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        # Exponential backoff with full jitter, capped so a retry never eats
        # most of the client's own timeout budget.
        delay = self._backoff_base * (2**attempt) + random.uniform(0, self._backoff_base)
        if retry_after is not None:
            delay = max(delay, retry_after)
        return min(delay, 2.0)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))  # delta-seconds form
    except ValueError:
        pass
    try:
        return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())  # HTTP-date form
    except (TypeError, ValueError):
        return None


# =============================================================================
# 7. Audit pipeline - Kafka producer and Kafka -> Postgres sink
# =============================================================================


class AuditProducer:
    """Fire-and-forget audit publishing.

    ``emit`` never blocks the request and never raises. Delivery is
    acknowledged by all in-sync replicas (acks=all + idempotence), which costs
    the client nothing because we do not await the acknowledgement. If Kafka is
    unreachable the event is written to the structured log instead, so the
    audit trail degrades to log shipping rather than disappearing.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._topic = settings.kafka_audit_topic
        self._producer: AIOKafkaProducer | None = None
        self._pending: set[asyncio.Task[None]] = set()

    @property
    def connected(self) -> bool:
        return self._producer is not None

    async def start(self, attempts: int = 5) -> None:
        if not self._settings.kafka_enabled:
            logger.info("kafka disabled; audit events go to the log")
            return
        for attempt in range(attempts):
            producer = AIOKafkaProducer(
                bootstrap_servers=self._settings.kafka_bootstrap_servers,
                client_id=f"{self._settings.app_name}-gateway",
                acks="all",
                enable_idempotence=True,
                linger_ms=self._settings.kafka_linger_ms,
                compression_type="gzip",
                request_timeout_ms=10_000,
            )
            try:
                await producer.start()
            except KafkaError:
                await producer.stop()
                logger.warning("kafka connect attempt %d/%d failed", attempt + 1, attempts)
                await asyncio.sleep(min(2**attempt, 10))
                continue
            self._producer = producer
            logger.info("kafka audit producer connected")
            return
        logger.error("kafka unavailable; running degraded (audit events go to the log)")

    def emit(self, event: AuditEvent) -> None:
        payload = event.model_dump_json().encode()
        if self._producer is None:
            logger.info("audit %s", payload.decode())
            return
        task = asyncio.create_task(self._send(event.tenant_id, payload))
        self._pending.add(task)  # hold a reference so the task isn't GC'd mid-flight
        task.add_done_callback(self._pending.discard)

    async def _send(self, key: str, payload: bytes) -> None:
        assert self._producer is not None
        try:
            # Awaiting send() only enqueues into the batch; the returned future
            # resolves on broker ack, which we observe via a callback.
            delivery = await self._producer.send(self._topic, value=payload, key=key.encode())
            delivery.add_done_callback(lambda f, p=payload: self._on_delivery(f, p))
        except Exception:  # noqa: BLE001
            logger.exception("audit enqueue failed; event=%s", payload.decode())

    @staticmethod
    def _on_delivery(future: asyncio.Future[Any], payload: bytes) -> None:
        if future.cancelled() or future.exception() is not None:
            logger.error("audit delivery failed; event=%s", payload.decode())

    async def stop(self) -> None:
        if self._pending:
            await asyncio.wait(self._pending, timeout=5)
        if self._producer is not None:
            await self._producer.stop()  # flushes buffered batches
            self._producer = None


async def run_audit_sink(settings: Settings | None = None) -> None:
    """Consume audit events and bulk-insert them into Postgres.

    At-least-once: offsets are committed only after the insert commits, and
    ``ON CONFLICT (request_id) DO NOTHING`` makes redelivery harmless. A
    database failure crashes the worker on purpose; the orchestrator restarts
    it and consumption resumes from the last committed offset.
    """
    from app.database import Datastores

    settings = settings or get_settings()
    stores = Datastores(settings)
    await stores.create_schema()

    consumer = AIOKafkaConsumer(
        settings.kafka_audit_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_consumer_group,
        client_id=f"{settings.app_name}-audit-sink",
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    await consumer.start()
    logger.info("audit sink consuming %s", settings.kafka_audit_topic)
    try:
        while True:
            batches = await consumer.getmany(timeout_ms=1000, max_records=500)
            if not batches:
                continue
            rows: list[dict[str, Any]] = []
            for records in batches.values():
                for record in records:
                    try:
                        rows.append(AuditEvent.model_validate_json(record.value).model_dump())
                    except ValidationError:
                        logger.error("dropping malformed audit record at offset %s", record.offset)
            if rows:
                async with stores.session_factory() as session:
                    await session.execute(
                        pg_insert(AuditLog).values(rows).on_conflict_do_nothing(index_elements=["request_id"])
                    )
                    await session.commit()
            await consumer.commit()
            logger.debug("persisted %d audit events", len(rows))
    finally:
        await consumer.stop()
        await stores.close()


if __name__ == "__main__":
    logging.basicConfig(level=get_settings().log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run_audit_sink())
