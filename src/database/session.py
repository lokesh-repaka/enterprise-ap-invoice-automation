"""
Async SQLAlchemy 2.0 Engine and Session Factory.

Supports portable switching between local SQLite (aiosqlite) and production
Azure SQL Serverless (aioodbc + Entra ID Managed Identity) via get_settings().
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from src.core.config import get_settings


def create_db_engine(database_url: str | None = None, echo: bool = False) -> AsyncEngine:
    """Create a configured SQLAlchemy 2.0 AsyncEngine."""
    url = database_url or get_settings().database_url

    if url.startswith("sqlite"):
        kwargs: dict = {
            "echo": echo,
            "connect_args": {"check_same_thread": False},
        }
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return create_async_engine(url, **kwargs)

    # Production Azure SQL configuration with connection health checks
    return create_async_engine(
        url,
        echo=echo,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=10,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a scoped AsyncSession per request."""
    engine = create_db_engine()
    session_factory = create_session_factory(engine)
    try:
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()
