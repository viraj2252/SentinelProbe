"""Logging configuration for SentinelProbe."""

import logging

from loguru import logger

from sentinelprobe.core.config import get_settings


def configure_logging() -> None:
    """Configure the application logging.

    Sets up loguru with appropriate log level and format.
    """
    settings = get_settings()

    # Remove default handlers
    logger.remove()

    # Add console handler
    logger.add(
        logging.StreamHandler(),
        level=settings.LOG_LEVEL,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # Add file handler for non-DEBUG logging
    if settings.LOG_LEVEL != "DEBUG":
        logger.add(
            "logs/sentinelprobe.log",
            rotation="10 MB",
            retention="1 week",
            level=settings.LOG_LEVEL,
            format=(
                "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
                "{level: <8} | "
                "{name}:{function}:{line} - "
                "{message}"
            ),
        )

    logger.info(f"Logging configured with level: {settings.LOG_LEVEL}")


def get_logger() -> "logger":
    """Get configured logger instance.

    Returns:
        logger: Configured loguru logger instance.
    """
    return logger
