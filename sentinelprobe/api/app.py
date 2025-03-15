"""FastAPI application for SentinelProbe."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.db import init_db
from sentinelprobe.core.logging import configure_logging, get_logger
from sentinelprobe.core.mongodb import close_mongo_connection, connect_to_mongo
from sentinelprobe.core.redis import close_redis_connection, connect_to_redis

logger = get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI application.

    Handles startup and shutdown events.

    Args:
        app: FastAPI application.
    """
    # Startup
    configure_logging()
    logger.info(f"Starting {settings.APP_NAME} API")

    # Initialize database connections
    try:
        await init_db()
        await connect_to_mongo()
        await connect_to_redis()
    except Exception as e:
        logger.error(f"Error initializing database connections: {e}")
        raise

    yield

    # Shutdown
    logger.info(f"Shutting down {settings.APP_NAME} API")

    # Close database connections
    await close_mongo_connection()
    await close_redis_connection()


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Penetration Testing System",
    version="0.1.0",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> dict:
    """Root endpoint.

    Returns:
        dict: Basic API information.
    """
    return {
        "name": settings.APP_NAME,
        "version": "0.1.0",
        "description": "AI-Powered Penetration Testing System",
    }


@app.get(f"{settings.API_PREFIX}/health")
async def health_check() -> dict:
    """Health check endpoint.

    Returns:
        dict: Health status information.
    """
    return {"status": "healthy"}
