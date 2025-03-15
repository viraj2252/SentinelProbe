"""Tests for the Service repository."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.reconnaissance.models import Port, ServiceType
from sentinelprobe.reconnaissance.repository import ServiceRepository
from tests.conftest import MockSession
from tests.reconnaissance.mock_repository import MockServiceRepository


@pytest_asyncio.fixture
async def session():
    """Create a mock session for testing."""
    return MockSession()


@pytest_asyncio.fixture
async def service_repository(session):
    """Create a service repository for testing."""
    return ServiceRepository(session)


@pytest_asyncio.fixture
async def mock_service_repository(session):
    """Create a mock service repository for testing."""
    return MockServiceRepository(session)


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

    @pytest.mark.asyncio
    async def test_get_services_by_target_and_type(
        self, mock_service_repository, session
    ):
        """Test getting services by target ID and service type."""
        # Arrange
        # Create a target
        target_id = 1

        # Create ports for the target
        port1 = Port(id=1, target_id=target_id, port_number=80, protocol="tcp")
        port2 = Port(id=2, target_id=target_id, port_number=443, protocol="tcp")
        port3 = Port(id=3, target_id=target_id, port_number=22, protocol="tcp")
        port4 = Port(
            id=4, target_id=2, port_number=80, protocol="tcp"
        )  # Different target

        # Initialize the session attributes
        session.ports = [port1, port2, port3, port4]
        session.services = []  # Initialize services list

        # Create services
        service1 = await mock_service_repository.create_service(
            port_id=1,
            service_type=ServiceType.HTTP,
            name="http",
            version="1.1",
            banner="Apache/2.4.41",
            metadata={"detected_by": "banner_scan"},
        )

        service2 = await mock_service_repository.create_service(
            port_id=2,
            service_type=ServiceType.HTTP,
            name="https",
            version="1.1",
            banner="nginx/1.18.0",
            metadata={"detected_by": "banner_scan"},
        )

        service3 = await mock_service_repository.create_service(
            port_id=3,
            service_type=ServiceType.SSH,
            name="ssh",
            version="OpenSSH_8.2p1",
            banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            metadata={"detected_by": "banner_scan"},
        )

        service4 = await mock_service_repository.create_service(
            port_id=4,
            service_type=ServiceType.HTTP,
            name="http",
            version="1.1",
            banner="Apache/2.4.41",
            metadata={"detected_by": "banner_scan"},
        )

        # Add them to session manually to ensure they're there
        session.services = [service1, service2, service3, service4]

        # Act
        http_services = await mock_service_repository.get_services_by_target_and_type(
            target_id=target_id, service_type=ServiceType.HTTP
        )

        ssh_services = await mock_service_repository.get_services_by_target_and_type(
            target_id=target_id, service_type=ServiceType.SSH
        )

        mysql_services = await mock_service_repository.get_services_by_target_and_type(
            target_id=target_id, service_type=ServiceType.MYSQL
        )

        # Assert
        assert len(http_services) == 2
        assert service1 in http_services
        assert service2 in http_services
        assert service4 not in http_services  # Different target

        assert len(ssh_services) == 1
        assert service3 in ssh_services

        assert len(mysql_services) == 0  # No MySQL services
