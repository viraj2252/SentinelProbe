"""Tests for the API module."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock


@pytest.fixture
def mock_client():
    """Create a test client with mocked database connections."""
    # Mock the database engine before importing the app
    engine_mock = MagicMock()
    engine_mock.begin.return_value.__aenter__.return_value = AsyncMock()
    
    with patch("sentinelprobe.core.db.engine", engine_mock), \
         patch("sentinelprobe.core.db.init_db", AsyncMock()), \
         patch("sentinelprobe.core.mongodb.connect_to_mongo", AsyncMock()), \
         patch("sentinelprobe.core.mongodb.close_mongo_connection", AsyncMock()), \
         patch("sentinelprobe.core.redis.connect_to_redis", AsyncMock()):
        
        # Import app after patching
        from sentinelprobe.api.app import app
        
        with TestClient(app) as test_client:
            yield test_client


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