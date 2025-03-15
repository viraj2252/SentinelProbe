"""Tests for the configuration module."""

import pytest

from sentinelprobe.core.config import Settings, get_settings


def test_settings_defaults() -> None:
    """Test default settings values."""
    # Create a settings instance with explicit values
    settings = Settings(DEBUG=False)
    assert settings.APP_NAME == "sentinelprobe"
    assert settings.DEBUG is False
    assert settings.API_PREFIX == "/api/v1"
    assert settings.POSTGRES_SERVER == "localhost"
    assert settings.POSTGRES_PORT == 5432
    assert settings.LOG_LEVEL == "INFO"


def test_postgres_dsn() -> None:
    """Test PostgreSQL DSN generation."""
    settings = Settings(
        POSTGRES_USER="testuser",
        POSTGRES_PASSWORD="testpass",
        POSTGRES_SERVER="testserver",
        POSTGRES_PORT=5433,
        POSTGRES_DB="testdb",
    )
    expected_dsn = "postgresql+asyncpg://testuser:testpass@testserver:5433/testdb"
    assert settings.postgres_dsn == expected_dsn


def test_log_level_validation() -> None:
    """Test log level validation."""
    # Valid log levels
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        settings = Settings(LOG_LEVEL=level)
        assert settings.LOG_LEVEL == level

    # Invalid log level
    with pytest.raises(ValueError):
        Settings(LOG_LEVEL="INVALID")


def test_get_settings_cache() -> None:
    """Test settings caching."""
    settings1 = get_settings()
    settings2 = get_settings()
    assert settings1 is settings2  # Same instance due to lru_cache
