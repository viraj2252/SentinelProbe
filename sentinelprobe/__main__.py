"""Main entry point for SentinelProbe."""

import argparse

from sentinelprobe.core.logging import configure_logging, get_logger

logger = get_logger(__name__)


def add_run_command(subparsers):
    """Add run command to argument parser."""
    run_parser = subparsers.add_parser("run", help="Run the application")
    return run_parser


def add_migrate_command(subparsers):
    """Add migrate command to argument parser."""
    migrate_parser = subparsers.add_parser("migrate", help="Run database migrations")
    return migrate_parser


def run_app(args):
    """Run the application."""
    configure_logging()
    logger.info("Starting SentinelProbe application")
    # Implementation will be added later


def run_migrations(args):
    """Run database migrations."""
    configure_logging()
    logger.info("Running database migrations")
    # Implementation will be added later


def main():
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
