"""Tests for the service detector module."""

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelprobe.reconnaissance.models import ServiceType
from sentinelprobe.reconnaissance.service_detector import ServiceDetector


class MockSocket:
    """Mock socket for testing."""

    def __init__(self, response_data=None):
        """Initialize the mock socket."""
        self.response_data = response_data or b""
        self.timeout = 1.0
        self.closed = False

    def settimeout(self, timeout):
        """Set the socket timeout."""
        self.timeout = timeout

    def connect(self, addr):
        """Connect to the target."""
        return None

    def connect_ex(self, addr):
        """Connect to the target and return a status code."""
        return 0

    def close(self):
        """Close the socket."""
        self.closed = True

    def recv(self, bufsize):
        """Receive data from the socket."""
        return self.response_data

    def sendall(self, data):
        """Send data to the socket."""
        pass


@pytest.fixture
def service_detector():
    """Create a ServiceDetector instance for testing."""
    return ServiceDetector(timeout=0.1)


@pytest.mark.asyncio
async def test_grab_banner_success():
    """Test grabbing a banner successfully."""
    # Mock socket with a successful response
    mock_socket = MockSocket(b"SSH-2.0-OpenSSH_8.2p1\r\n")

    with patch("socket.socket", return_value=mock_socket):
        detector = ServiceDetector(timeout=0.1)
        banner = await detector.grab_banner("127.0.0.1", 22)

        assert banner == "SSH-2.0-OpenSSH_8.2p1\r\n"


@pytest.mark.asyncio
async def test_grab_banner_failure():
    """Test grabbing a banner with a failure."""
    # Mock socket with an exception
    with patch("socket.socket") as mock_socket_class:
        mock_socket_class.side_effect = socket.timeout("Connection timed out")

        detector = ServiceDetector(timeout=0.1)
        banner = await detector.grab_banner("127.0.0.1", 22)

        assert banner == ""


@pytest.mark.asyncio
async def test_probe_service_success():
    """Test probing a service successfully."""
    # Mock socket with a successful response
    mock_socket = MockSocket(b"220 smtp.example.com ESMTP\r\n")

    with patch("socket.socket", return_value=mock_socket):
        detector = ServiceDetector(timeout=0.1)
        response = await detector.probe_service(
            "127.0.0.1", 25, b"EHLO example.com\r\n"
        )

        assert response == "220 smtp.example.com ESMTP\r\n"


@pytest.mark.asyncio
async def test_probe_service_failure():
    """Test probing a service with a failure."""
    # Mock socket with an exception
    with patch("socket.socket") as mock_socket_class:
        mock_socket_class.side_effect = socket.timeout("Connection timed out")

        detector = ServiceDetector(timeout=0.1)
        response = await detector.probe_service(
            "127.0.0.1", 25, b"EHLO example.com\r\n"
        )

        assert response == ""


def test_identify_service_type():
    """Test identifying service type from a banner."""
    detector = ServiceDetector()

    # Test SSH banner
    service_type, name = detector.identify_service_type("SSH-2.0-OpenSSH_8.2p1")
    assert service_type == ServiceType.SSH
    assert name == "SSH"

    # Test HTTP banner
    service_type, name = detector.identify_service_type(
        "HTTP/1.1 200 OK\r\nServer: nginx"
    )
    assert service_type == ServiceType.HTTP
    assert name == "HTTP"

    # Test unknown banner
    service_type, name = detector.identify_service_type("Unknown banner")
    assert service_type == ServiceType.UNKNOWN
    assert name == "Unknown"


def test_extract_version():
    """Test extracting version from a banner."""
    detector = ServiceDetector()

    # Test SSH version extraction
    version = detector.extract_version("SSH-2.0-OpenSSH_8.2p1", ServiceType.SSH)
    assert version == "OpenSSH_8.2p1"

    # Test HTTP version extraction
    version = detector.extract_version(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", ServiceType.HTTP
    )
    assert version == "nginx/1.18.0"

    # Test no version found
    version = detector.extract_version("No version here", ServiceType.SSH)
    assert version == ""


@pytest.mark.asyncio
async def test_detect_service_known_port():
    """Test detecting a service on a known port."""
    # Mock successful banner grab with an SSH service
    with patch.object(
        ServiceDetector, "grab_banner", return_value="SSH-2.0-OpenSSH_8.2p1"
    ):
        detector = ServiceDetector()
        result = await detector.detect_service("127.0.0.1", 22)

        assert result["service_type"] == ServiceType.SSH
        assert result["name"] == "SSH"
        assert result["version"] == "OpenSSH_8.2p1"
        assert result["banner"] == "SSH-2.0-OpenSSH_8.2p1"


@pytest.mark.asyncio
async def test_detect_service_with_probing():
    """Test detecting a service using probing."""
    # Mock initial banner grab failure, then successful probe
    with patch.object(ServiceDetector, "grab_banner", return_value=""):
        with patch.object(
            ServiceDetector,
            "probe_service",
            return_value="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        ):
            detector = ServiceDetector()
            result = await detector.detect_service("127.0.0.1", 80)

            assert result["service_type"] == ServiceType.HTTP
            assert result["name"] == "HTTP"
            assert result["version"] == "nginx/1.18.0"
            assert result["banner"] == "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"


@pytest.mark.asyncio
async def test_detect_service_unknown():
    """Test detecting an unknown service."""
    # Mock both banner grab and probing failures
    with patch.object(ServiceDetector, "grab_banner", return_value=""):
        with patch.object(ServiceDetector, "probe_service", return_value=""):
            detector = ServiceDetector()
            result = await detector.detect_service("127.0.0.1", 12345)

            assert result["service_type"] == ServiceType.UNKNOWN
            assert result["name"] == "Unknown"
            assert result["version"] == ""
            assert result["banner"] == ""


@pytest.mark.asyncio
async def test_detect_services_batch():
    """Test detecting multiple services in a batch."""

    async def mock_detect_service(ip, port, protocol=None):
        if port == 22:
            return {
                "service_type": ServiceType.SSH,
                "name": "SSH",
                "version": "OpenSSH_8.2p1",
                "banner": "SSH-2.0-OpenSSH_8.2p1",
            }
        elif port == 80:
            return {
                "service_type": ServiceType.HTTP,
                "name": "HTTP",
                "version": "nginx/1.18.0",
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            }
        else:
            return {
                "service_type": ServiceType.UNKNOWN,
                "name": "Unknown",
                "version": "",
                "banner": "",
            }

    with patch.object(ServiceDetector, "detect_service", mock_detect_service):
        detector = ServiceDetector()
        results = await detector.detect_services_batch("127.0.0.1", [22, 80, 8080])

        assert len(results) == 3
        assert results[22]["service_type"] == ServiceType.SSH
        assert results[80]["service_type"] == ServiceType.HTTP
        assert results[8080]["service_type"] == ServiceType.UNKNOWN


@pytest.mark.asyncio
async def test_generic_version_extraction():
    """Test generic version pattern extraction."""
    # Test with a banner that doesn't have a specific pattern but has a version string
    with patch.object(
        ServiceDetector, "grab_banner", return_value="Custom Service v1.2.3"
    ):
        detector = ServiceDetector()
        result = await detector.detect_service("127.0.0.1", 9999)

        assert result["version"] == "v1.2.3"
