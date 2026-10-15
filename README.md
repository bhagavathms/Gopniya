# Gopniya (गोपनीय) 🛡️
> A high-throughput, low-latency enterprise AI Gateway and Security Proxy.

*Gopniya* means **confidential**. It sits between your applications and LLM
providers and gives you, in one OpenAI-compatible hop:

- 🔐 **PII & secret protection:** emails, cards (Luhn-validated), Aadhaar (Verhoeff), SSN, PAN, phones, IPs, private keys, cloud and API tokens and JWTs are redacted *before* they leave your network, and again in model responses.
- 🧱 **Prompt-injection blocking:** weighted heuristics reject instruction-override and system-prompt-exfiltration attempts.
- ⏱️ **Distributed rate limiting:** a per-tenant token bucket enforced atomically in Redis with a Lua script, correct across any number of replicas.
- ♻️ **Resilience:** retries with jittered backoff, per-provider circuit breakers, and automatic failover to a fallback provider.
- 💸 **Cost control:** a tenant-scoped exact-match response cache, plus per-request token usage attribution.
- 📜 **Audit trail:** one event per request streamed through Kafka into PostgreSQL, off the hot path. Raw prompts are never stored.
- 🔌 **Drop-in:** existing OpenAI SDK clients only change `base_url` and `api_key`.

---

## 📌 Project Status
✅ **Core gateway complete:** all four milestones are implemented and verified end to end.

---

## 🏗️ Architecture

```
Client ──► Gopniya ──► auth ──► rate limit ──► guardrails ──► cache ──► forwarder ──┬──► Primary LLM
 (OpenAI    (FastAPI,  (Redis   (Redis Lua     (regex +        (Redis)   (httpx HTTP/2, └──► Fallback LLM
  SDK)       asyncio)   + PG)    token bucket)  heuristics)               circuit breakers)
                │
                └── audit event (fire-and-forget) ──► Kafka ──► audit-sink ──► PostgreSQL
```

| Request outcome | Status |
|---|---|
| Missing / invalid API key | `401` |
| Prompt injection, or PII when the policy is `block` | `400 content_policy_violation` |
| Prompt over the size cap | `413` |
| Tenant over quota | `429` + `Retry-After` |
| All providers failing / circuits open | `502` / `503` |

Every response carries `X-Request-ID`, `X-RateLimit-*`, `X-Gopniya-Guardrail`
and, for cacheable requests, `X-Gopniya-Cache`.

---

## 🛠️ Tech Stack
* **Core:** Python 3.12, FastAPI, Pydantic v2, Uvicorn (uvloop), `httpx` (HTTP/2)
* **State & Caching:** Redis 7 (token-bucket rate limiting via Lua, auth and response caching)
* **Messaging:** Apache Kafka 3.8, KRaft mode (audit and telemetry events)
* **Database:** PostgreSQL 16, SQLAlchemy 2.0 (async, asyncpg)
* **Containerization:** Docker & Docker Compose

---

## 📁 Repository Layout
```
app/
  config.py      Typed settings (GOPNIYA_* env vars)
  database.py    Async SQLAlchemy engine + Redis connection pool
  models.py      ORM tables + Pydantic request/response/audit schemas
  services.py    Auth, rate limiter, cache, guardrails, forwarder + circuit breaker,
                 Kafka producer, and the Kafka→Postgres audit sink
  main.py        FastAPI app, lifespan, /v1/chat/completions, health probes
test_gateway.py  In-process test suite (no external services needed)
docker-compose.yml, Dockerfile, requirements.txt
```

---

## 🗺️ Roadmap
- [x] **Milestone 1:** Core Asynchronous Proxy (`/v1/chat/completions`, streaming + non-streaming)
- [x] **Milestone 2:** Guardrails & PII Scrubbing (requests and responses)
- [x] **Milestone 3:** Redis Distributed Rate Limiting & Exact-Match Caching
- [x] **Milestone 4:** Circuit Breakers & Kafka Telemetry Pipeline
- [ ] Token-based quotas (charge estimated tokens, reconcile with `usage`)
- [ ] Streaming output PII scanning (sliding-window redactor)
- [ ] Async ML guardrails on the Kafka stream
- [ ] Alembic migrations, non-OpenAI provider adapters

---

## 🚀 Getting Started

**Prerequisites:** Docker Desktop (running), and an OpenAI-compatible API key
or a local [Ollama](https://ollama.com) model.

```bash
# 1. Point Gopniya at a provider
export OPENAI_API_KEY=sk-...                  # PowerShell: $env:OPENAI_API_KEY="sk-..."

# 2. Start gateway, audit-sink, Postgres, Redis and Kafka
docker compose up --build -d --wait           # if port 8000 is busy: GATEWAY_PORT=8088

# 3. Check health
curl http://localhost:8000/readyz

# 4. Send a request containing PII (the email is redacted before it leaves)
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer gpn-dev-key" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi, I am jane@acme.com"}]}'
```

Using the OpenAI SDK:
```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="gpn-dev-key")
```

**Using a local model instead (Ollama):** set
`UPSTREAM_BASE_URL=http://host.docker.internal:11434/v1` and
`OPENAI_API_KEY=ollama`, then use e.g. `"model": "llama3.2"`.

**See what happened:**
```bash
docker compose exec postgres psql -U gopniya -d gopniya \
  -c "select status_code, guardrail_action, guardrail_findings, latency_ms from audit_logs order by created_at desc limit 5;"
```

**Shut down:** `docker compose down` (add `-v` to delete data).

---

## 🧪 Testing
```bash
pip install -r requirements.txt pytest
pytest -v test_gateway.py
```
The suite runs the real gateway in-process with in-memory fakes for Redis and
the LLM provider. It covers authentication (401), prompt-injection blocking
(400), PII masking in both directions, and rate limiting (429).

---

## ⚙️ Configuration
All settings are environment variables prefixed with `GOPNIYA_` (or a `.env`
file). The full list is in [app/config.py](app/config.py).

| Variable | Default | Purpose |
|---|---|---|
| `GOPNIYA_UPSTREAM_BASE_URL` / `_API_KEY` | OpenAI | Primary provider |
| `GOPNIYA_FALLBACK_BASE_URL` / `_API_KEY` / `_MODEL` | unset | Fallback provider and model rewrite |
| `GOPNIYA_RATE_LIMIT_CAPACITY` / `_REFILL_PER_SECOND` | `60` / `1.0` | Token bucket burst / sustained rate |
| `GOPNIYA_GUARDRAIL_PII_ACTION` | `redact` | `redact`, `block` or `allow` |
| `GOPNIYA_CACHE_ENABLED` | `true` | Exact-match cache for `temperature: 0` requests |
| `GOPNIYA_CIRCUIT_FAILURE_THRESHOLD` / `_RECOVERY_SECONDS` | `5` / `30` | Circuit breaker tuning |
| `GOPNIYA_BOOTSTRAP_API_KEY` | `gpn-dev-key` (compose) | API key seeded at startup |

---

## 🧭 Key Design Decisions
| Area | Choice | Why |
|---|---|---|
| Concurrency | FastAPI + asyncio | LLM calls are long and I/O-bound; coroutines hold thousands of streams cheaply |
| Rate limiting | Redis token bucket in one Lua script | Atomic across replicas, one round-trip, burst-friendly, uses Redis's clock |
| Guardrails | Inline regex + checksums + heuristics | About 0.3 ms per prompt and deterministic; ML guardrails cost 50–500 ms per request |
| Audit | Kafka, fire-and-forget, idempotent sink | Zero hot-path latency, durable (`acks=all`), replayable fan-out |
| Upstream | Raw `httpx` + circuit breakers + fallback | Transparent pass-through, safe retries only, fast fail-over |
