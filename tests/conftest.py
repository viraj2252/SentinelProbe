"""Pytest configuration for SentinelProbe tests."""

import os
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from sentinelprobe.api.app import app as fastapi_app


class MockEngine:
    """Mock SQLAlchemy engine for testing."""
    
    async def begin(self):
        """Mock begin method."""
        class MockConnection:
            async def __aenter__(self):
                return AsyncMock()
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            
            async def run_sync(self, callable_):
                pass
        
        return MockConnection()


class MockMongoClient:
    """Mock MongoDB client for testing."""
    
    def __init__(self):
        """Initialize the mock client."""
        self.admin = AsyncMock()
        self.admin.command = AsyncMock()
        self.close = MagicMock()  # Not async
        self._db = AsyncMock()
    
    def __getitem__(self, key):
        """Support subscripting to get database."""
        return self._db


@pytest.fixture(autouse=True)
def mock_db_dependencies():
    """Mock database dependencies for testing."""
    # Mock the engine creation
    with patch("sentinelprobe.core.db.create_async_engine") as mock_engine_factory:
        mock_engine_factory.return_value = MockEngine()
        
        # Mock MongoDB
        with patch("sentinelprobe.core.mongodb.AsyncIOMotorClient") as mock_mongo_factory:
            mock_mongo_client = MockMongoClient()
            mock_mongo_factory.return_value = mock_mongo_client
            
            # Mock Redis
            with patch("sentinelprobe.core.redis.redis.Redis") as mock_redis:
                mock_redis.return_value = AsyncMock()
                
                yield


@pytest.fixture
def app() -> FastAPI:
    """Get FastAPI application.

    Returns:
        FastAPI: Application instance.
    """
    return fastapi_app


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Get test client for FastAPI application.

    Args:
        app: FastAPI application.

    Yields:
        TestClient: Test client instance.
    """
    with TestClient(app) as test_client:
        yield test_client 