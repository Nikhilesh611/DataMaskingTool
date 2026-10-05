"""Async SQLAlchemy 2.0 engine and session factory.

Environment-driven URL selection:
  DATABASE_URL env var → use as-is (supports postgresql+asyncpg:// for prod).
  Fallback            → SQLite async database at ``data/masking.db``.

Usage
-----
In FastAPI lifespan:
    from app.db.session import init_db, get_session
    await init_db()                         # Creates tables on first run

In route handlers (via Depends):
    async def my_route(db: AsyncSession = Depends(get_session)):
        ...
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from dotenv import load_dotenv

load_dotenv()

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base

# ── Engine ─────────────────────────────────────────────────────────────────────

def _build_url() -> str:
    """Resolve PostgreSQL database URL from env or default to Docker PostgreSQL container."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        if not (url.startswith("postgresql") or url.startswith("postgres")):
            raise ValueError(
                f"Invalid DATABASE_URL scheme '{url}'. The enterprise masking platform strictly requires Docker PostgreSQL."
            )
        return url
    # Default: Enterprise PostgreSQL container running on host port 5433
    return "postgresql+asyncpg://masking_admin:masking_secure_password@localhost:5433/masking_db"


# Built lazily so tests/config can configure DATABASE_URL before first call.
_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine():
    """Return the singleton async PostgreSQL engine, creating it on first call."""
    global _engine
    if _engine is None:
        url = _build_url()
        _engine = create_async_engine(
            url,
            echo=False,
            pool_pre_ping=True,
            pool_size=20,
            max_overflow=10,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the singleton session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


# ── Lifecycle ──────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables (idempotent — safe to call on every startup).

    In production use proper Alembic migrations.  For development and tests
    ``create_all`` is sufficient.
    """
    # Import models so SQLAlchemy registers them against Base.metadata.
    import app.db.models  # noqa: F401

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose engine connection pool (call on shutdown)."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


# ── FastAPI dependency ─────────────────────────────────────────────────────────

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async generator yielding a database session for use as a FastAPI Depends."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
