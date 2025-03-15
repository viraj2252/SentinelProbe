"""Tests for the Reconnaissance scanner module."""

import asyncio
import random
import socket
import time
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
        scan_rate=0.1,  # Fast scanning for tests
        jitter=0.05,
        max_concurrent_scans=5,
        timeout=0.1,
        aggressive_mode=False,
    )


@pytest_asyncio.fixture
async def aggressive_scanner_service(mock_repositories):
    """Create an aggressive PortScannerService for testing."""
    return PortScannerService(
        mock_repositories["target_repo"],
        mock_repositories["port_repo"],
        mock_repositories["service_repo"],
        scan_rate=0.0,
        jitter=0.0,
        max_concurrent_scans=100,
        timeout=0.1,
        aggressive_mode=True,
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
    async def test_scan_port_with_custom_timeout(self, port_scanner_service):
        """Test scanning a port with a custom timeout."""
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0

        with patch("socket.socket", return_value=mock_socket):
            port, status = await port_scanner_service.scan_port(
                "192.0.2.1", 80, timeout=3.0
            )

            assert port == 80
            assert status == PortStatus.OPEN
            mock_socket.close.assert_called_once()
            # Verify socket was created with the custom timeout
            assert mock_socket.settimeout.call_args[0][0] == 3.0

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

        # Mock sleep to avoid waiting during tests
        with patch("asyncio.sleep", AsyncMock()):
            # Call scan_target
            result = await port_scanner_service.scan_target(1, [80])

            # Verify target was updated
            assert result == mock_target
            target_repo.update_target.assert_called()

            # Verify status was updated to COMPLETED
            status_calls = [
                call[1].get("status")
                for call in target_repo.update_target.call_args_list
                if "status" in call[1]
            ]
            assert TargetStatus.COMPLETED in status_calls

            # Verify metadata was updated with scan information
            metadata_calls = [
                call[1].get("metadata")
                for call in target_repo.update_target.call_args_list
                if "metadata" in call[1]
            ]
            assert any(
                "total_ports_scanned" in metadata
                for metadata in metadata_calls
                if metadata
            )
            assert any(
                "scan_completed_at" in metadata
                for metadata in metadata_calls
                if metadata
            )

    @pytest.mark.asyncio
    async def test_scan_target_rate_limited(
        self, port_scanner_service, mock_repositories
    ):
        """Test scanning a target with rate limiting."""
        # Set a very small max_concurrent_scans to force batching
        port_scanner_service.max_concurrent_scans = 2
        port_scanner_service.aggressive_mode = False

        # Create a list of ports that will require multiple batches
        test_ports = [80, 443, 8080, 22, 21, 25, 53, 110, 143]

        # Mock scan_port to simulate different port statuses
        async def mock_scan_port(ip, port, timeout=None):
            if port == 80:
                return port, PortStatus.OPEN
            elif port == 443:
                return port, PortStatus.OPEN
            else:
                return port, PortStatus.CLOSED

        port_scanner_service.scan_port = AsyncMock(side_effect=mock_scan_port)

        # Mock detect_service to return service info
        service_info = {
            "service_type": ServiceType.HTTP,
            "name": "HTTP",
            "version": "1.1",
            "banner": "Test Server",
        }
        port_scanner_service.detect_service = AsyncMock(return_value=service_info)

        # Mock sleep to avoid waiting during tests
        sleep_mock = AsyncMock()
        with patch("asyncio.sleep", sleep_mock):
            # Call scan_target with multiple ports
            await port_scanner_service.scan_target(1, test_ports)

            # Verify sleep was called at least once (for rate limiting)
            assert sleep_mock.called

    @pytest.mark.asyncio
    async def test_scan_target_aggressive_mode(
        self, aggressive_scanner_service, mock_repositories
    ):
        """Test scanning a target in aggressive mode."""
        # Mock scan_port to simulate different port statuses
        async def mock_scan_port(ip, port, timeout=None):
            if port == 80:
                return port, PortStatus.OPEN
            elif port == 443:
                return port, PortStatus.OPEN
            else:
                return port, PortStatus.CLOSED

        aggressive_scanner_service.scan_port = AsyncMock(side_effect=mock_scan_port)

        # Mock detect_service to return service info
        service_info = {
            "service_type": ServiceType.HTTP,
            "name": "HTTP",
            "version": "1.1",
            "banner": "Test Server",
        }
        aggressive_scanner_service.detect_service = AsyncMock(return_value=service_info)

        # Mock sleep to track if it's called
        sleep_mock = AsyncMock()
        with patch("asyncio.sleep", sleep_mock):
            # Call scan_target with multiple ports in aggressive mode
            await aggressive_scanner_service.scan_target(1, [80, 443, 8080, 22, 21])

            # Verify sleep was not called (aggressive mode doesn't use rate limiting)
            assert not sleep_mock.called
