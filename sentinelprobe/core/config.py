"""Configuration management for SentinelProbe."""

import os
from functools import lru_cache
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    """Application settings.

    Attributes:
        APP_NAME: Name of the application.
        DEBUG: Debug mode flag.
        API_PREFIX: Prefix for API routes.
        POSTGRES_SERVER: PostgreSQL server hostname.
        POSTGRES_USER: PostgreSQL username.
        POSTGRES_PASSWORD: PostgreSQL password.
        POSTGRES_DB: PostgreSQL database name.
        POSTGRES_PORT: PostgreSQL server port.
        MONGODB_URL: MongoDB connection URL.
        REDIS_HOST: Redis server hostname.
        REDIS_PORT: Redis server port.
        REDIS_PASSWORD: Redis server password.
        LOG_LEVEL: Logging level.
    """

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=True
    )

    APP_NAME: str = "sentinelprobe"
    DEBUG: bool = Field(default=False)
    API_PREFIX: str = "/api/v1"

    # PostgreSQL settings
    POSTGRES_SERVER: str = Field(default="localhost")
    POSTGRES_USER: str = Field(default="postgres")
    POSTGRES_PASSWORD: str = Field(default="postgres")
    POSTGRES_DB: str = Field(default="sentinelprobe")
    POSTGRES_PORT: int = Field(default=5432)

    # MongoDB settings
    MONGODB_URL: str = Field(default="mongodb://localhost:27017/sentinelprobe")

    # Redis settings
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_PASSWORD: Optional[str] = Field(default=None)

    # Logging
    LOG_LEVEL: str = Field(default="INFO")

    @property
    def postgres_dsn(self) -> str:
        """Generate PostgreSQL DSN from settings.

        Returns:
            str: PostgreSQL connection string.
        """
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level.

        Args:
            v: Log level value.

        Returns:
            str: Validated log level.

        Raises:
            ValueError: If log level is invalid.
        """
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    """Get application settings with caching.

    Returns:
        Settings: Application settings instance.
    """
    return Settings() 