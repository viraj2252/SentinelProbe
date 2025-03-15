"""Tests for the Service repository."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.reconnaissance.models import ServiceType
from sentinelprobe.reconnaissance.repository import ServiceRepository
from tests.conftest import MockSession


@pytest_asyncio.fixture
async def session():
    """Create a mock session for testing."""
    return MockSession()


@pytest_asyncio.fixture
async def service_repository(session):
    """Create a service repository for testing."""
    return ServiceRepository(session)


class TestServiceRepository:
    """Tests for the Service repository."""

    @pytest.mark.asyncio
    async def test_create_service(self, service_repository):
        """Test creating a service."""
        # Arrange
        port_id = 1
        service_type = ServiceType.HTTP
        name = "http"
        version = "1.1"
        banner = "Apache/2.4.41"
        metadata = {"detected_by": "banner_scan"}

        # Act
        service = await service_repository.create_service(
            port_id=port_id,
            service_type=service_type,
            name=name,
            version=version,
            banner=banner,
            metadata=metadata,
        )

        # Assert
        assert service is not None
        assert service.id is not None
        assert service.port_id == port_id
        assert service.service_type == service_type
        assert service.name == name
        assert service.version == version
        assert service.banner == banner
        assert service.service_metadata == metadata
        assert service.created_at is not None
