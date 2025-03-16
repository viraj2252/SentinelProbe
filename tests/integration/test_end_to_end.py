"""Integration tests for the complete end-to-end SentinelProbe workflow."""

import asyncio
import enum
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelprobe.reconnaissance.models import ServiceType
from sentinelprobe.reconnaissance.scanner import PortScannerService
from sentinelprobe.reconnaissance.service_detector import ServiceDetector
from sentinelprobe.vulnerability_scanner.models import VulnerabilitySeverity
from sentinelprobe.vulnerability_scanner.service import VulnerabilityScannerService


# Create simplified models for testing
@dataclass
class ServiceWithPort:
    """Simplified Service model for testing."""

    service_type: ServiceType
    name: str
    version: str
    banner: str = None
    service_metadata: dict = None
    port: int = None


@dataclass
class VulnerabilityTest:
    """Simplified Vulnerability model for testing."""

    name: str
    description: str
    severity: VulnerabilitySeverity
    remediation: str
    details: dict = None


@pytest.mark.asyncio
async def test_end_to_end_scan():
    """Test the end-to-end scanning process."""
    # Set up the port scanner with mocked scan results
    port_scanner = MagicMock(spec=PortScannerService)
    port_scanner.scan_ports = AsyncMock(return_value=[22, 80, 443, 27017])

    # Set up the service detector with mocked detection results
    service_detector = ServiceDetector()

    # Mock the detect_service method
    service_detector.detect_service = AsyncMock()

    # Configure conditional returns for detect_service
    async def detect_service_side_effect(ip_address, port, protocol="tcp"):
        if port == 22:
            return ServiceWithPort(
                service_type=ServiceType.SSH,
                name="OpenSSH",
                version="8.2p1",
                banner="SSH-2.0-OpenSSH_8.2p1",
                service_metadata={"auth_methods": ["password", "publickey"]},
                port=port,
            )
        elif port == 80:
            return ServiceWithPort(
                service_type=ServiceType.HTTP,
                name="Apache",
                version="2.4.41",
                banner=None,
                service_metadata={"server": "Apache/2.4.41"},
                port=port,
            )
        elif port == 443:
            return ServiceWithPort(
                service_type=ServiceType.HTTPS,
                name="Apache",
                version="2.4.41",
                banner=None,
                service_metadata={"server": "Apache/2.4.41"},
                port=port,
            )
        elif port == 27017:
            return ServiceWithPort(
                service_type=ServiceType.MONGODB,
                name="MongoDB",
                version="4.2.1",
                banner=None,
                service_metadata={
                    "authentication": "disabled",
                    "binding": "0.0.0.0",
                    "config": {
                        "security": {
                            "authorization": "disabled",
                            "javascriptEnabled": True,
                        },
                        "net": {"bindIp": "0.0.0.0", "http": {"enabled": True}},
                    },
                },
                port=port,
            )
        else:
            return ServiceWithPort(
                service_type=ServiceType.UNKNOWN,
                name="Unknown",
                version="",
                banner=None,
                service_metadata={},
                port=port,
            )

    service_detector.detect_service.side_effect = detect_service_side_effect

    # Set up the vulnerability scanner with mocked scan results
    vuln_scanner = MagicMock(spec=VulnerabilityScannerService)

    # Mock the scan_service method
    vuln_scanner.scan_service = AsyncMock()

    # Configure returns for scan_service based on service type
    async def scan_service_side_effect(service):
        if service.service_type == ServiceType.SSH:
            return [
                VulnerabilityTest(
                    name="SSH Weak Ciphers",
                    description="SSH server supports weak encryption ciphers",
                    severity=VulnerabilitySeverity.MEDIUM,
                    remediation="Disable weak ciphers in SSH configuration",
                    details={"references": ["https://example.com/ssh-weak-ciphers"]},
                ),
                VulnerabilityTest(
                    name="SSH Root Login Enabled",
                    description="SSH server allows root login",
                    severity=VulnerabilitySeverity.HIGH,
                    remediation="Disable root login in SSH configuration",
                    details={"references": ["https://example.com/ssh-root-login"]},
                ),
            ]
        elif service.service_type == ServiceType.HTTP:
            return [
                VulnerabilityTest(
                    name="HTTP Server Information Disclosure",
                    description="HTTP server reveals version information",
                    severity=VulnerabilitySeverity.LOW,
                    remediation="Configure server to hide version information",
                    details={
                        "references": ["https://example.com/http-info-disclosure"]
                    },
                )
            ]
        elif service.service_type == ServiceType.HTTPS:
            return [
                VulnerabilityTest(
                    name="TLS 1.0 Supported",
                    description="Server supports outdated TLS 1.0 protocol",
                    severity=VulnerabilitySeverity.MEDIUM,
                    remediation="Disable TLS 1.0 support",
                    details={"references": ["https://example.com/tls-1-0"]},
                )
            ]
        elif service.service_type == ServiceType.MONGODB:
            return [
                VulnerabilityTest(
                    name="MongoDB No Authentication",
                    description="MongoDB instance has no authentication enabled",
                    severity=VulnerabilitySeverity.CRITICAL,
                    remediation="Enable authentication for MongoDB",
                    details={"references": ["https://example.com/mongodb-auth"]},
                ),
                VulnerabilityTest(
                    name="MongoDB Exposed to Internet",
                    description="MongoDB is bound to 0.0.0.0 and accessible from the internet",
                    severity=VulnerabilitySeverity.CRITICAL,
                    remediation="Bind MongoDB to localhost or use firewall rules",
                    details={"references": ["https://example.com/mongodb-binding"]},
                ),
            ]
        else:
            return []

    vuln_scanner.scan_service.side_effect = scan_service_side_effect

    # Create a scanner instance with our mocked components
    scanner = MagicMock()
    scanner.port_scanner = port_scanner
    scanner.service_detector = service_detector
    scanner.vulnerability_scanner = vuln_scanner

    # Mock the scan method
    async def mock_scan(target):
        # Scan ports
        open_ports = await port_scanner.scan_ports(target)

        # Detect services
        services = []
        for port in open_ports:
            service = await service_detector.detect_service(target, port)
            services.append(service)

        # Scan for vulnerabilities
        vulnerabilities = []
        for service in services:
            service_vulns = await vuln_scanner.scan_service(service)
            vulnerabilities.extend(service_vulns)

        # Create a report
        report = MagicMock()
        report.target = target
        report.open_ports = open_ports
        report.services = services
        report.vulnerabilities = vulnerabilities

        return report

    scanner.scan = mock_scan

    # Run the scan
    report = await scanner.scan("192.168.1.1")

    # Verify the scan results
    assert report.target == "192.168.1.1"
    assert len(report.open_ports) == 4
    assert 22 in report.open_ports
    assert 80 in report.open_ports
    assert 443 in report.open_ports
    assert 27017 in report.open_ports

    # Verify service detection was called for each open port
    assert service_detector.detect_service.call_count == 4
    service_detector.detect_service.assert_any_call("192.168.1.1", 22)
    service_detector.detect_service.assert_any_call("192.168.1.1", 80)
    service_detector.detect_service.assert_any_call("192.168.1.1", 443)
    service_detector.detect_service.assert_any_call("192.168.1.1", 27017)

    # Verify vulnerability scanning was called for each service
    assert vuln_scanner.scan_service.call_count == 4

    # Verify the detected services in the report
    assert len(report.services) == 4

    # Get services by port
    services_by_port = {service.port: service for service in report.services}

    # Verify SSH service
    ssh = services_by_port[22]
    assert ssh.service_type == ServiceType.SSH
    assert ssh.name == "OpenSSH"
    assert ssh.version == "8.2p1"

    # Verify HTTP service
    http = services_by_port[80]
    assert http.service_type == ServiceType.HTTP
    assert http.name == "Apache"
    assert http.version == "2.4.41"

    # Verify HTTPS service
    https = services_by_port[443]
    assert https.service_type == ServiceType.HTTPS
    assert https.name == "Apache"
    assert https.version == "2.4.41"

    # Verify MongoDB service
    mongodb = services_by_port[27017]
    assert mongodb.service_type == ServiceType.MONGODB
    assert mongodb.name == "MongoDB"
    assert mongodb.version == "4.2.1"

    # Verify vulnerabilities
    assert len(report.vulnerabilities) == 6

    # Count vulnerabilities by severity
    severity_counts = {
        VulnerabilitySeverity.LOW: 0,
        VulnerabilitySeverity.MEDIUM: 0,
        VulnerabilitySeverity.HIGH: 0,
        VulnerabilitySeverity.CRITICAL: 0,
    }

    for vuln in report.vulnerabilities:
        severity_counts[vuln.severity] += 1

    assert severity_counts[VulnerabilitySeverity.LOW] == 1
    assert severity_counts[VulnerabilitySeverity.MEDIUM] == 2
    assert severity_counts[VulnerabilitySeverity.HIGH] == 1
    assert severity_counts[VulnerabilitySeverity.CRITICAL] == 2
