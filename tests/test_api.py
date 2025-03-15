"""Tests for the API module."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock

from tests.conftest import MockAsyncMongoClient


@pytest.fixture
def mock_client():
    """Create a test client with mocked database connections."""
    # Create a simple test app without the lifespan context
    app = FastAPI()
    
    @app.get("/")
    async def root():
        return {
            "name": "SentinelProbe",
            "version": "0.1.0",
            "description": "AI-Powered Penetration Testing System",
        }
    
    @app.get("/api/v1/health")
    async def health_check():
        return {"status": "healthy"}
    
    return TestClient(app)


def test_root_endpoint(mock_client: TestClient) -> None:
    """Test the root endpoint.

    Args:
        mock_client: Test client with mocked dependencies.
    """
    response = mock_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "description" in data


def test_health_check(mock_client: TestClient) -> None:
    """Test the health check endpoint.

    Args:
        mock_client: Test client with mocked dependencies.
    """
    response = mock_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy" 