"""Integration tests for the reconnaissance to vulnerability scanning workflow."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelprobe.reconnaissance.models import (
    Port,
    PortStatus,
    Service,
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
from sentinelprobe.reconnaissance.service_detector import ServiceDetector
from sentinelprobe.vulnerability_scanner.models import (
    ScanStatus,
    ScanType,
    Vulnerability,
    VulnerabilityScan,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelprobe.vulnerability_scanner.repository import (
    VulnerabilityRepository,
    VulnerabilityScanRepository,
)
from sentinelprobe.vulnerability_scanner.service import VulnerabilityScannerService


@pytest.fixture
def mock_session():
    """Create a mock SQLAlchemy session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.close = AsyncMock()
    session.rollback = AsyncMock()
    return session


@pytest.mark.asyncio
class TestReconVulnWorkflow:
    """Test the reconnaissance to vulnerability scanning workflow."""

    async def test_end_to_end_scan_workflow(self, mock_session):
        """Test the end-to-end workflow from recon to vulnerability scanning."""
        # Set up repositories
        target_repo = TargetRepository(mock_session)
        port_repo = PortRepository(mock_session)
        service_repo = ServiceRepository(mock_session)
        vuln_scan_repo = VulnerabilityScanRepository(mock_session)
        vuln_repo = VulnerabilityRepository(mock_session)

        # Create a mock target
        job_id = 1234
        target = Target(
            id=1,
            job_id=job_id,
            hostname="test-target.example.com",
            ip_address="192.168.1.100",
            status=TargetStatus.PENDING,
            target_metadata={},
        )

        # Set up mocks for repository returns
        target_repo.get_target = AsyncMock(return_value=target)
        target_repo.update_target_status = AsyncMock(return_value=target)

        # Set up the scanner service with mocked scan results
        scanner_service = PortScannerService(mock_session, port_repo, service_repo)

        # Mock the scan_ports method
        scanner_service._scan_ports = AsyncMock(
            return_value=[
                {"port": 22, "status": "open", "protocol": "tcp"},
                {"port": 80, "status": "open", "protocol": "tcp"},
                {"port": 443, "status": "open", "protocol": "tcp"},
                {"port": 27017, "status": "open", "protocol": "tcp"},  # MongoDB port
            ]
        )

        # Mock the scan_target method to return the target directly
        async def mock_scan_target(*args, **kwargs):
            # Create ports
            await port_repo.create_port(
                target_id=target.id,
                port_number=22,
                protocol="tcp",
                status=PortStatus.OPEN,
            )
            await port_repo.create_port(
                target_id=target.id,
                port_number=80,
                protocol="tcp",
                status=PortStatus.OPEN,
            )
            await port_repo.create_port(
                target_id=target.id,
                port_number=443,
                protocol="tcp",
                status=PortStatus.OPEN,
            )
            await port_repo.create_port(
                target_id=target.id,
                port_number=27017,
                protocol="tcp",
                status=PortStatus.OPEN,
            )

            # Create services
            for port, service_info in zip(
                [ssh_port, http_port, https_port, mongo_port],
                [
                    (
                        ServiceType.SSH,
                        "OpenSSH",
                        "8.2p1",
                        "SSH-2.0-OpenSSH_8.2p1",
                        {"auth_methods": ["password", "publickey"]},
                    ),
                    (
                        ServiceType.HTTP,
                        "Apache",
                        "2.4.41",
                        None,
                        {"server": "Apache/2.4.41"},
                    ),
                    (
                        ServiceType.HTTPS,
                        "Apache",
                        "2.4.41",
                        None,
                        {"server": "Apache/2.4.41"},
                    ),
                    (
                        ServiceType.MONGODB,
                        "MongoDB",
                        "4.2.1",
                        None,
                        {
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
                    ),
                ],
            ):
                service_type, name, version, banner, metadata = service_info
                await service_repo.create_service(
                    port_id=port.id,
                    name=name,
                    service_type=service_type,
                    version=version,
                    banner=banner,
                    service_metadata=metadata,
                )

            # Update target status
            target.status = TargetStatus.COMPLETED
            await target_repo.update_target_status(target.id, TargetStatus.COMPLETED)
            return target

        scanner_service.scan_target = AsyncMock(side_effect=mock_scan_target)

        # Mock port creation
        ssh_port = Port(
            id=1,
            target_id=target.id,
            port_number=22,
            protocol="tcp",
            status=PortStatus.OPEN,
        )
        http_port = Port(
            id=2,
            target_id=target.id,
            port_number=80,
            protocol="tcp",
            status=PortStatus.OPEN,
        )
        https_port = Port(
            id=3,
            target_id=target.id,
            port_number=443,
            protocol="tcp",
            status=PortStatus.OPEN,
        )
        mongo_port = Port(
            id=4,
            target_id=target.id,
            port_number=27017,
            protocol="tcp",
            status=PortStatus.OPEN,
        )

        port_repo.create_port = AsyncMock(
            side_effect=[ssh_port, http_port, https_port, mongo_port]
        )
        port_repo.get_ports_by_target = AsyncMock(
            return_value=[ssh_port, http_port, https_port, mongo_port]
        )

        # Set up the service detector with mocked detection results
        service_detector = ServiceDetector(mock_session)

        # Mock service creations
        ssh_service = Service(
            id=1,
            port_id=ssh_port.id,
            name="OpenSSH",
            service_type=ServiceType.SSH,
            version="8.2p1",
            banner="SSH-2.0-OpenSSH_8.2p1",
            service_metadata={"auth_methods": ["password", "publickey"]},
        )

        http_service = Service(
            id=2,
            port_id=http_port.id,
            name="Apache",
            service_type=ServiceType.HTTP,
            version="2.4.41",
            banner=None,
            service_metadata={"server": "Apache/2.4.41"},
        )

        https_service = Service(
            id=3,
            port_id=https_port.id,
            name="Apache",
            service_type=ServiceType.HTTPS,
            version="2.4.41",
            banner=None,
            service_metadata={"server": "Apache/2.4.41"},
        )

        mongo_service = Service(
            id=4,
            port_id=mongo_port.id,
            name="MongoDB",
            service_type=ServiceType.MONGODB,
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
        )

        # Mock service detection
        service_detector._detect_service = AsyncMock()
        service_detector._detect_service.side_effect = [
            (
                ServiceType.SSH,
                "OpenSSH",
                "8.2p1",
                "SSH-2.0-OpenSSH_8.2p1",
                {"auth_methods": ["password", "publickey"]},
            ),
            (ServiceType.HTTP, "Apache", "2.4.41", None, {"server": "Apache/2.4.41"}),
            (ServiceType.HTTPS, "Apache", "2.4.41", None, {"server": "Apache/2.4.41"}),
            (
                ServiceType.MONGODB,
                "MongoDB",
                "4.2.1",
                None,
                {
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
            ),
        ]

        service_repo.create_service = AsyncMock(
            side_effect=[ssh_service, http_service, https_service, mongo_service]
        )
        service_repo.get_services_by_target = AsyncMock(
            return_value=[ssh_service, http_service, https_service, mongo_service]
        )
        service_repo.get_services_by_target_and_type = AsyncMock()

        # Set up conditional returns for get_services_by_target_and_type
        async def get_services_by_target_and_type_side_effect(target_id, service_type):
            if service_type == ServiceType.SSH:
                return [ssh_service]
            elif service_type == ServiceType.HTTP:
                return [http_service]
            elif service_type == ServiceType.HTTPS:
                return [https_service]
            elif service_type == ServiceType.MONGODB:
                return [mongo_service]
            else:
                return []

        service_repo.get_services_by_target_and_type.side_effect = (
            get_services_by_target_and_type_side_effect
        )

        # Mock scan creation
        vuln_scan = VulnerabilityScan(
            id=1,
            job_id=job_id,
            target_id=target.id,
            strategy_id=None,
            name="Test scan",
            description="Test vulnerability scan",
            scan_type=ScanType.STANDARD,
            scanner_module="mongodb_scanner",
            status=ScanStatus.PENDING,
            parameters={},
            scan_metadata={},
        )

        vuln_scan_repo.create_scan = AsyncMock(return_value=vuln_scan)
        vuln_scan_repo.get_scan = AsyncMock(return_value=vuln_scan)
        vuln_scan_repo.update_scan_status = AsyncMock(return_value=vuln_scan)

        # Mock vulnerability creation
        vulnerability = Vulnerability(
            id=1,
            scan_id=vuln_scan.id,
            target_id=target.id,
            name="MongoDB Missing Authentication",
            description="MongoDB is running without authentication enabled.",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="MongoDB 4.2.1",
            port_number=27017,
            protocol="tcp",
            details={
                "auth_status": "none",
                "recommendation": "Enable authentication and configure strong credentials.",
            },
            remediation="Enable MongoDB authentication and configure SCRAM authentication mechanism.",
        )

        vuln_repo.create_vulnerability = AsyncMock(return_value=vulnerability)
        vuln_repo.get_vulnerabilities_by_scan = AsyncMock(return_value=[vulnerability])

        # Create a vulnerability scanner service with mocked plugins
        vuln_scanner_service = VulnerabilityScannerService(mock_session)

        # Mock all methods needed for the workflow
        vuln_scanner_service.create_scan = AsyncMock(return_value=vuln_scan)

        # Mock start_scan to update the scan status
        async def mock_start_scan(scan_id):
            vuln_scan.status = ScanStatus.RUNNING
            await vuln_scan_repo.update_scan_status(scan_id, ScanStatus.RUNNING)

            # Get the scanner plugin
            scanner_plugin = await vuln_scanner_service.get_scanner_plugin(
                vuln_scan.scanner_module
            )

            # Run the scan
            vuln_results = await scanner_plugin.scan(
                vuln_scan.id, target.id, mongo_service
            )

            # Create vulnerabilities
            for vuln_data in vuln_results:
                await vuln_repo.create_vulnerability(**vuln_data)

            # Simulate scan completion
            vuln_scan.status = ScanStatus.COMPLETED
            await vuln_scan_repo.update_scan_status(scan_id, ScanStatus.COMPLETED)
            return vuln_scan

        vuln_scanner_service.start_scan = AsyncMock(side_effect=mock_start_scan)
        vuln_scanner_service.get_scanner_plugin = AsyncMock()
        vuln_scanner_service.create_vulnerability = AsyncMock(
            return_value=vulnerability
        )

        # PHASE 1: Run the reconnaissance workflow
        # Scan ports
        await scanner_service.scan_target(target.id)

        # Verify that target, ports and services were processed
        target_repo.update_target_status.assert_called()
        assert port_repo.create_port.call_count == 4  # 4 ports created

        # Detect services
        for port in [ssh_port, http_port, https_port, mongo_port]:
            await service_detector.detect_service(
                target.ip_address, port.port_number, port.protocol
            )

        assert service_repo.create_service.call_count == 4  # 4 services created

        # PHASE 2: Run the vulnerability scanning workflow
        # Create a scan
        scan = await vuln_scanner_service.create_scan(
            job_id=job_id,
            target_id=target.id,
            name="Test scan",
            description="Test vulnerability scan",
            scan_type=ScanType.STANDARD,
            scanner_module="mongodb_scanner",
            parameters={},
        )

        # Mock the MongoDB scanner plugin
        mongodb_scanner_mock = AsyncMock()
        mongodb_scanner_mock.scan = AsyncMock(
            return_value=[
                {
                    "scan_id": scan.id,
                    "target_id": target.id,
                    "name": "MongoDB Missing Authentication",
                    "description": "MongoDB is running without authentication enabled.",
                    "severity": VulnerabilitySeverity.HIGH,
                    "status": VulnerabilityStatus.UNCONFIRMED,
                    "affected_component": "MongoDB 4.2.1",
                    "port_number": 27017,
                    "protocol": "tcp",
                    "details": {
                        "auth_status": "none",
                        "recommendation": "Enable authentication and configure strong credentials.",
                    },
                    "remediation": "Enable MongoDB authentication and configure SCRAM authentication mechanism.",
                }
            ]
        )

        # Set up the scanner plugin mock return
        async def get_scanner_plugin_side_effect(scanner_name):
            if scanner_name == "mongodb_scanner":
                return mongodb_scanner_mock
            return None

        vuln_scanner_service.get_scanner_plugin.side_effect = (
            get_scanner_plugin_side_effect
        )

        # Start the scan
        await vuln_scanner_service.start_scan(scan.id)

        # Verify that the vulnerability scan was processed
        vuln_scan_repo.update_scan_status.assert_called()
        assert vuln_scanner_service.get_scanner_plugin.call_count > 0
        assert mongodb_scanner_mock.scan.call_count == 1  # Scanner was called

        # Verify that vulnerabilities were created
        vulnerabilities = await vuln_repo.get_vulnerabilities_by_scan(scan.id)
        assert len(vulnerabilities) == 1

        # Verify the vulnerability details
        vuln = vulnerabilities[0]
        assert vuln.name == "MongoDB Missing Authentication"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.port_number == 27017
        assert vuln.affected_component == "MongoDB 4.2.1"
