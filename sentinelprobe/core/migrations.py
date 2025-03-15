"""Database migrations module for SentinelProbe."""

import asyncio
from typing import List, Optional

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelprobe.core.db import Base, engine
from sentinelprobe.core.logging import get_logger

logger = get_logger()


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
    """Create database schema based on SQLAlchemy models.

    Args:
        engine_instance: SQLAlchemy engine. If None, use the default engine.

    Returns:
        List[str]: List of created tables.
    """
    logger.info("Creating database schema")
    
    # Use provided engine or default
    engine_to_use = engine_instance or engine
    
    # Get tables before creation
    tables_before = await get_tables(engine_to_use)
    logger.debug(f"Tables before creation: {tables_before}")
    
    # Create all tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Get tables after creation
    tables_after = await get_tables(engine_to_use)
    logger.debug(f"Tables after creation: {tables_after}")
    
    # Determine which tables were created
    created_tables = [table for table in tables_after if table not in tables_before]
    
    if created_tables:
        logger.info(f"Created tables: {', '.join(created_tables)}")
    else:
        logger.info("No new tables created")
    
    return created_tables


async def drop_schema(engine_instance: Optional[AsyncEngine] = None) -> List[str]:
    """Drop all tables in the database.

    Args:
        engine_instance: SQLAlchemy engine. If None, use the default engine.

    Returns:
        List[str]: List of dropped tables.
    """
    logger.warning("Dropping all tables from the database")
    
    # Use provided engine or default
    engine_to_use = engine_instance or engine
    
    # Get tables before dropping
    tables_before = await get_tables(engine_to_use)
    logger.debug(f"Tables before dropping: {tables_before}")
    
    # Drop all tables
    async with engine_to_use.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # Get tables after dropping
    tables_after = await get_tables(engine_to_use)
    logger.debug(f"Tables after dropping: {tables_after}")
    
    # Determine which tables were dropped
    dropped_tables = [table for table in tables_before if table not in tables_after]
    
    if dropped_tables:
        logger.info(f"Dropped tables: {', '.join(dropped_tables)}")
    else:
        logger.info("No tables were dropped")
    
    return dropped_tables


async def recreate_schema(engine_instance: Optional[AsyncEngine] = None) -> tuple[List[str], List[str]]:
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


async def run_migration(migration_name: Optional[str] = None, engine_instance: Optional[AsyncEngine] = None) -> List[str]:
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