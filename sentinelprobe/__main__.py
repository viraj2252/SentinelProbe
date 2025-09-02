"""Main entry point for SentinelProbe."""

import argparse
import asyncio
import os
from argparse import ArgumentParser, Namespace, _SubParsersAction
from typing import cast

from sentinelprobe.core.db import get_engine
from sentinelprobe.core.logging import configure_logging, get_logger
from sentinelprobe.core.migrations import MigrationManager, create_schema

logger = get_logger(__name__)


def add_run_command(subparsers: _SubParsersAction) -> ArgumentParser:
    """Add run command to argument parser."""
    run_parser = subparsers.add_parser("run", help="Run the application")
    return cast(ArgumentParser, run_parser)


def add_migrate_command(subparsers: _SubParsersAction) -> ArgumentParser:
    """Add migrate command to argument parser."""
    migrate_parser = subparsers.add_parser("migrate", help="Run database migrations")
    migrate_subparsers = migrate_parser.add_subparsers(
        dest="action", help="Migration action"
    )

    # Add upgrade command
    _ = migrate_subparsers.add_parser("upgrade", help="Apply migrations")

    # Add init command
    _ = migrate_subparsers.add_parser("init", help="Initialize database schema")

    return cast(ArgumentParser, migrate_parser)


def run_app(args: Namespace) -> None:
    """Run the application."""
    configure_logging()
    logger.info("Starting SentinelProbe application")
    # Start FastAPI via uvicorn
    try:
        import uvicorn

        host = os.getenv("HOST", "0.0.0.0")
        port_str = os.getenv("PORT", "8000")
        port = int(port_str) if port_str.isdigit() else 8000
        uvicorn.run("sentinelprobe.api.app:app", host=host, port=port, log_level="info")
    except Exception as e:
        logger.error(f"Failed to start API: {e}")
        raise


async def _run_migrations_async(action: str) -> None:
    """Run database migrations asynchronously.

    Args:
        action: Migration action (upgrade, init)
    """
    engine = get_engine()

    if action == "init":
        logger.info("Initializing database schema")
        created_tables = await create_schema(engine)
        logger.info(f"Created tables: {', '.join(created_tables)}")
    elif action == "upgrade":
        logger.info("Running database migrations")
        migration_manager = MigrationManager(engine)
        await migration_manager.apply_migrations()
        logger.info("Migrations completed successfully")
    else:
        logger.error(f"Unknown migration action: {action}")


def run_migrations(args: Namespace) -> None:
    """Run database migrations.

    Args:
        args: Command-line arguments
    """
    configure_logging()

    # Default to 'upgrade' when action flag is omitted or parsed as None
    action = getattr(args, "action", None) or "upgrade"

    # Run migrations asynchronously
    asyncio.run(_run_migrations_async(action))


def main() -> None:
    """Run the main application."""
    parser = argparse.ArgumentParser(
        description="SentinelProbe - Monitoring and Alerting System"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Add commands
    add_run_command(subparsers)
    add_migrate_command(subparsers)

    args = parser.parse_args()

    if args.command == "run":
        run_app(args)
    elif args.command == "migrate":
        run_migrations(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
