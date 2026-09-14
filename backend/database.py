"""Async SQLAlchemy database engine, session factory, and base model."""
from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_tables() -> None:
    """Create all tables. Called during app startup."""
    # Import models to register them with Base.metadata
    from .threats.models import ThreatScore, AuditOverride  # noqa: F401
    from .auth.token_store import StoredToken  # noqa: F401
    from .agent.models import AgentChatSession, AgentChatMessage  # noqa: F401

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for col in ["geo_lat", "geo_lon"]:
            try:
                await conn.exec_driver_sql(f"ALTER TABLE threat_scores ADD COLUMN {col} FLOAT")
            except Exception:
                pass
        for col_name, col_type in [("detected_language", "VARCHAR(64)"), ("language_code", "VARCHAR(16)")]:
            try:
                await conn.exec_driver_sql(f"ALTER TABLE threat_scores ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass


async def close_db() -> None:
    """Dispose engine connections. Called during app shutdown."""
    engine = get_engine()
    await engine.dispose()
