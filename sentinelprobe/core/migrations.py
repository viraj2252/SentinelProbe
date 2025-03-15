"""Database migration utilities."""

import asyncio
import importlib.util
from pathlib import PurePath
from typing import List, Optional, Set

from sqlalchemy import inspect, text
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
    """Create database schema.

    Args:
        engine_instance: Optional SQLAlchemy engine.

    Returns:
        List[str]: List of created tables.
    """
    engine_to_use = engine_instance or get_engine()

    # Get tables before creation
    tables_before = set()
    async with engine_to_use.begin() as conn:
        result = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        tables_before = {row[0] for row in result.fetchall()}

    # Create all tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Get tables after creation
    tables_after = set()
    async with engine_to_use.begin() as conn:
        result = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        tables_after = {row[0] for row in result.fetchall()}

    # Return list of created tables
    created_tables = list(tables_after - tables_before)
    logger.info(f"Created tables: {created_tables}")
    return created_tables


async def drop_schema(engine_instance: Optional[AsyncEngine] = None) -> List[str]:
    """Drop database schema.

    Args:
        engine_instance: Optional SQLAlchemy engine.

    Returns:
        List[str]: List of dropped tables.
    """
    engine_to_use = engine_instance or get_engine()

    # Get tables before dropping
    inspector = inspect(engine_to_use)
    tables_before = await inspector.get_table_names()

    # Drop all tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # Get tables after dropping
    inspector = inspect(engine_to_use)
    tables_after = await inspector.get_table_names()

    # Return list of dropped tables
    dropped_tables = list(set(tables_before) - set(tables_after))
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

        # Check if the module has a direct_sql_upgrade function
        # If not, we'll assume it has tables defined in upgrade_tables()
        if hasattr(migration_module, "direct_sql_upgrade"):
            # Execute the SQL statements directly
            async with self.engine.begin() as conn:
                for sql_statement in migration_module.direct_sql_upgrade():
                    await conn.execute(text(sql_statement))

                # Record the migration as applied
                await conn.execute(
                    text(
                        """
                        INSERT INTO migrations (name, applied_at)
                        VALUES (:name, NOW())
                        """
                    ),
                    {"name": migration_name},
                )

                logger.info(f"Applied migration: {migration_name}")
        else:
            logger.error(
                f"Migration {migration_name} does not have a direct_sql_upgrade function"
            )

            # Record that we attempted but failed the migration
            async with self.engine.begin() as conn:
                await conn.execute(
                    text(
                        """
                        INSERT INTO migrations (name, applied_at)
                        VALUES (:name, NOW())
                        """
                    ),
                    {"name": f"FAILED_{migration_name}"},
                )

            raise NotImplementedError(
                f"Migration {migration_name} does not have a direct_sql_upgrade function"
            )

    async def apply_migrations(self) -> None:
        """Apply all pending migrations."""
        # Ensure migrations table exists
        applied_migrations = await self._get_applied_migrations()

        # Get all migration files
        from pathlib import Path

        # Get the directory where migrations are stored
        migrations_dir = Path(__file__).parent / "migrations" / "versions"

        if not migrations_dir.exists():
            logger.warning(f"Migrations directory not found: {migrations_dir}")
            return

        # Get all migration files
        migration_files = sorted(
            [f for f in migrations_dir.iterdir() if f.is_file() and f.suffix == ".py"]
        )

        if not migration_files:
            logger.info("No migration files found")
            return

        # Apply pending migrations
        for migration_file in migration_files:
            migration_name = migration_file.name
            if migration_name in applied_migrations:
                logger.info(f"Migration already applied: {migration_name}")
                continue

            logger.info(f"Applying migration: {migration_name}")
            await self._apply_migration(migration_file)

        logger.info("All migrations applied successfully")
