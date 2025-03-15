"""Main entry point for SentinelProbe application."""

import uvicorn

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.logging import configure_logging, get_logger

logger = get_logger()


def main() -> None:
    """Run the SentinelProbe application."""
    configure_logging()
    settings = get_settings()

    logger.info(f"Starting {settings.APP_NAME} in {'debug' if settings.DEBUG else 'production'} mode")
    
    uvicorn.run(
        "sentinelprobe.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main() 