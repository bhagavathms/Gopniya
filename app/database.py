"""Connection-pool ownership for PostgreSQL (async SQLAlchemy) and Redis.

Pools are created exactly once per process inside the FastAPI lifespan and
torn down on shutdown. Nothing here is a module-level global, which keeps
tests and the standalone audit sink free to build their own instances.
"""

from __future__ import annotations

import logging

import redis.asyncio as redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings

logger = logging.getLogger(__name__)

# Arbitrary constant: serialises schema creation across uvicorn workers.
_SCHEMA_LOCK_ID = 727_274_001


class Datastores:
    """Owns the SQLAlchemy engine and the Redis connection pool."""

    def __init__(self, settings: Settings) -> None:
        self.engine: AsyncEngine = create_async_engine(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,  # transparently replace connections killed by PG/LB
            pool_recycle=1800,
        )
        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
        self.redis_pool: redis.ConnectionPool = redis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=settings.redis_max_connections,
            socket_timeout=settings.redis_socket_timeout,
            socket_connect_timeout=1.0,
            health_check_interval=30,
            decode_responses=True,
        )
        self.redis: redis.Redis = redis.Redis(connection_pool=self.redis_pool)

    async def create_schema(self) -> None:
        """Create tables if missing. Dev convenience; use Alembic in production."""
        from app.models import Base  # local import avoids a models<->database cycle

        async with self.engine.begin() as conn:
            # Several workers boot at once; a transaction-scoped advisory lock
            # stops them racing on CREATE TABLE.
            await conn.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _SCHEMA_LOCK_ID})
            await conn.run_sync(Base.metadata.create_all)

    async def health(self) -> dict[str, bool]:
        status = {"postgres": False, "redis": False}
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            status["postgres"] = True
        except Exception:  # noqa: BLE001 - health probes must never raise
            logger.warning("postgres health check failed", exc_info=True)
        try:
            status["redis"] = bool(await self.redis.ping())
        except Exception:  # noqa: BLE001
            logger.warning("redis health check failed", exc_info=True)
        return status

    async def close(self) -> None:
        await self.redis.aclose()
        await self.redis_pool.disconnect()
        await self.engine.dispose()
