"""Tests for the Reconnaissance scanner module."""

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from sentinelprobe.reconnaissance.models import (
    PortStatus,
    ServiceType,
    Target,
    TargetStatus,
)
from sentinelprobe.reconnaissance.repository import (
    PortRepository,
    ServiceRepository,
    TargetRepository,
)
from sentinelprobe.reconnaissance.scanner import PortScannerService
from tests.conftest import MockSession


@pytest_asyncio.fixture
async def mock_repositories():
    """Create mock repositories for testing."""
    target_repo = AsyncMock(spec=TargetRepository)
    port_repo = AsyncMock(spec=PortRepository)
    service_repo = AsyncMock(spec=ServiceRepository)

    # Mock target
    mock_target = MagicMock(spec=Target)
    mock_target.id = 1
    mock_target.job_id = 1
    mock_target.hostname = "example.com"
    mock_target.ip_address = "192.0.2.1"
    mock_target.status = TargetStatus.PENDING
    mock_target.target_metadata = {}

    # Setup repository responses
    target_repo.get_target.return_value = mock_target
    target_repo.update_target.return_value = mock_target

    # Create a port object when port is created
    async def create_port_mock(*args, **kwargs):
        mock_port = MagicMock()
        mock_port.id = 1
        mock_port.target_id = kwargs.get("target_id", 1)
        mock_port.port_number = kwargs.get("port_number", 80)
        mock_port.protocol = kwargs.get("protocol", "tcp")
        mock_port.status = kwargs.get("status", PortStatus.CLOSED)
        return mock_port

    port_repo.create_port = create_port_mock

    # Create a service object when service is created
    async def create_service_mock(*args, **kwargs):
        mock_service = MagicMock()
        mock_service.id = 1
        mock_service.port_id = kwargs.get("port_id", 1)
        mock_service.service_type = kwargs.get("service_type", ServiceType.HTTP)
        mock_service.name = kwargs.get("name", "http")
        mock_service.version = kwargs.get("version", "1.1")
        mock_service.banner = kwargs.get("banner", "")
        mock_service.service_metadata = kwargs.get("metadata", {})
        return mock_service

    service_repo.create_service = create_service_mock

    return {
        "target_repo": target_repo,
        "port_repo": port_repo,
        "service_repo": service_repo,
        "mock_target": mock_target,
    }


@pytest_asyncio.fixture
async def port_scanner_service(mock_repositories):
    """Create a PortScannerService for testing."""
    return PortScannerService(
        mock_repositories["target_repo"],
        mock_repositories["port_repo"],
        mock_repositories["service_repo"],
    )


class TestPortScannerService:
    """Tests for the PortScannerService."""

    @pytest.mark.asyncio
    async def test_resolve_hostname(self, port_scanner_service):
        """Test resolving a hostname to an IP address."""
        # Mock socket.getaddrinfo to return a known IP
        mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))]

        with patch("asyncio.to_thread", AsyncMock(return_value=mock_addr_info)):
            result = await port_scanner_service.resolve_hostname("example.com")

            assert result == "192.0.2.1"

    @pytest.mark.asyncio
    async def test_resolve_hostname_failure(self, port_scanner_service):
        """Test hostname resolution failure."""
        with patch("asyncio.to_thread", AsyncMock(side_effect=socket.gaierror())):
            result = await port_scanner_service.resolve_hostname("nonexistent.example")

            assert result is None

    @pytest.mark.asyncio
    async def test_scan_port_open(self, port_scanner_service):
        """Test scanning an open port."""
        # Mock socket.connect_ex to return 0 (success)
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0

        with patch("socket.socket", return_value=mock_socket):
            port, status = await port_scanner_service.scan_port("192.0.2.1", 80)

            assert port == 80
            assert status == PortStatus.OPEN
            mock_socket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_port_closed(self, port_scanner_service):
        """Test scanning a closed port."""
        # Mock socket.connect_ex to return non-zero (failure)
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        with patch("socket.socket", return_value=mock_socket):
            port, status = await port_scanner_service.scan_port("192.0.2.1", 80)

            assert port == 80
            assert status == PortStatus.CLOSED
            mock_socket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_port_filtered(self, port_scanner_service):
        """Test scanning a filtered port."""
        # Mock socket.connect_ex to raise timeout
        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = socket.timeout()

        with patch("socket.socket", return_value=mock_socket):
            port, status = await port_scanner_service.scan_port("192.0.2.1", 80)

            assert port == 80
            assert status == PortStatus.FILTERED

    @pytest.mark.asyncio
    async def test_detect_service_known_port(self, port_scanner_service):
        """Test detecting a service on a known port."""
        # Port 80 is in common_ports dictionary as HTTP
        result = await port_scanner_service.detect_service("192.0.2.1", 80, "tcp")

        assert result is not None
        assert result["service_type"] == ServiceType.HTTP
        assert result["name"] == "HTTP"

    @pytest.mark.asyncio
    async def test_detect_service_unknown_port(self, port_scanner_service):
        """Test detecting a service on an unknown port."""
        # Port 12345 is not in common_ports dictionary
        result = await port_scanner_service.detect_service("192.0.2.1", 12345, "tcp")

        # Method returns None for unknown ports
        assert result is None

    @pytest.mark.asyncio
    async def test_scan_target_with_hostname(
        self, port_scanner_service, mock_repositories
    ):
        """Test scanning a target with hostname resolution."""
        target_repo = mock_repositories["target_repo"]
        mock_target = mock_repositories["mock_target"]

        # Mock resolve_hostname to return IP
        port_scanner_service.resolve_hostname = AsyncMock(return_value="192.0.2.1")

        # Mock scan_port to return open port
        port_scanner_service.scan_port = AsyncMock(return_value=(80, PortStatus.OPEN))

        # Mock detect_service to return service info
        service_info = {
            "service_type": ServiceType.HTTP,
            "name": "HTTP",
            "version": "1.1",
            "banner": "Test Server",
        }
        port_scanner_service.detect_service = AsyncMock(return_value=service_info)

        # Call scan_target
        result = await port_scanner_service.scan_target(1, [80])

        # Verify target was updated
        assert result == mock_target
        target_repo.update_target.assert_called()

        # Verify status was updated
        last_call_args = target_repo.update_target.call_args_list[-1][1]
        assert last_call_args["status"] == TargetStatus.COMPLETED
