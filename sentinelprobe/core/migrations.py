"""Database migration utilities."""

import asyncio
import importlib.util
import inspect
from pathlib import PurePath
from typing import List, Optional, Set

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelprobe.core.db import Base, get_engine
from sentinelprobe.core.logging import get_logger

logger = get_logger(__name__)


async def get_tables(engine_instance: AsyncEngine) -> List[str]:
    """Get all tables in the database.

    Args:
        engine_instance: SQLAlchemy engine.

    Returns:
        List[str]: List of table names.
    """
    async with engine_instance.connect() as conn:
        inspector = inspect(engine_instance)
        return await conn.run_sync(lambda sync_conn: inspector.get_table_names())


async def table_exists(engine_instance: AsyncEngine, table_name: str) -> bool:
    """Check if a table exists in the database.

    Args:
        engine_instance: SQLAlchemy engine.
        table_name: Name of the table to check.

    Returns:
        bool: True if the table exists, False otherwise.
    """
    tables = await get_tables(engine_instance)
    return table_name in tables


async def create_schema(engine_instance: Optional[AsyncEngine] = None) -> List[str]:
    """
    Create database schema.

    Args:
        engine_instance: Optional SQLAlchemy engine instance

    Returns:
        List[str]: List of created tables
    """
    # Use provided engine or default
    engine_to_use = engine_instance or get_engine()

    # Get tables before creation
    inspector = inspect(engine_to_use)
    tables_before = await inspector.get_table_names()

    # Create tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Get tables after creation
    inspector = inspect(engine_to_use)
    tables_after = await inspector.get_table_names()

    # Return list of created tables
    created_tables = [t for t in tables_after if t not in tables_before]
    return created_tables


async def drop_schema(engine_instance: Optional[AsyncEngine] = None) -> List[str]:
    """
    Drop database schema.

    Args:
        engine_instance: Optional SQLAlchemy engine instance

    Returns:
        List[str]: List of dropped tables
    """
    # Use provided engine or default
    engine_to_use = engine_instance or get_engine()

    # Get tables before dropping
    inspector = inspect(engine_to_use)
    tables_before = await inspector.get_table_names()

    # Drop tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # Get tables after dropping
    inspector = inspect(engine_to_use)
    tables_after = await inspector.get_table_names()

    # Return list of dropped tables
    dropped_tables = [t for t in tables_before if t not in tables_after]
    return dropped_tables


async def recreate_schema(
    engine_instance: Optional[AsyncEngine] = None,
) -> tuple[List[str], List[str]]:
    """Drop and recreate all tables in the database.

    Args:
        engine_instance: SQLAlchemy engine. If None, use the default engine.

    Returns:
        tuple[List[str], List[str]]: Tuple of (dropped tables, created tables).
    """
    logger.warning("Recreating database schema")

    # Drop all tables
    dropped_tables = await drop_schema(engine_instance)

    # Create all tables
    created_tables = await create_schema(engine_instance)

    return dropped_tables, created_tables


async def run_migration(
    migration_name: Optional[str] = None, engine_instance: Optional[AsyncEngine] = None
) -> List[str]:
    """Run a specific migration or create the schema if no migration is specified.

    Args:
        migration_name: Name of the migration to run. If None, create the schema.
        engine_instance: SQLAlchemy engine. If None, use the default engine.

    Returns:
        List[str]: List of created tables.
    """
    if migration_name:
        logger.info(f"Running migration: {migration_name}")
        # In the future, this would run a specific migration
        # For now, we just create the schema
        return await create_schema(engine_instance)
    else:
        # Create the schema
        return await create_schema(engine_instance)


if __name__ == "__main__":
    """Run migrations when the module is executed directly."""
    asyncio.run(create_schema())


class MigrationManager:
    """Manages database migrations."""

    def __init__(self, engine: AsyncEngine):
        """
        Initialize migration manager.

        Args:
            engine: SQLAlchemy engine instance
        """
        self.engine = engine

    async def _get_applied_migrations(self) -> Set[str]:
        """Get a set of migrations that have already been applied."""
        async with self.engine.begin() as conn:
            # Create migrations table if it doesn't exist
            await conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS migrations (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        applied_at TIMESTAMP NOT NULL
                    )
                    """
                )
            )

            # Get applied migrations
            result = await conn.execute(text("SELECT name FROM migrations"))
            return {row[0] for row in result.fetchall()}

    async def _apply_migration(self, migration_path: PurePath) -> None:
        """Apply a single migration file."""
        migration_name = migration_path.name

        # Load the migration module
        spec = importlib.util.spec_from_file_location(
            f"migration_{migration_name}", migration_path
        )

        if not spec or not spec.loader:
            raise ImportError(f"Could not load migration: {migration_path}")

        migration_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration_module)
