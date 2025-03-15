"""Database module for SentinelProbe."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.logging import get_logger

logger = get_logger()
settings = get_settings()


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


# Create async engine
engine = create_async_engine(
    settings.postgres_dsn,
    echo=settings.DEBUG,
    future=True,
)

# Create session factory
async_session_factory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session.

    Yields:
        AsyncSession: Database session.
    """
    session = async_session_factory()
    try:
        yield session
    finally:
        await session.close()


async def init_db() -> None:
    """Initialize database.

    Creates all tables if they don't exist.
    """
    logger.info("Initializing database")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized")


def get_engine() -> AsyncEngine:
    """Get the SQLAlchemy engine instance.

    Returns:
        AsyncEngine: The global SQLAlchemy engine instance.
    """
    return engine
