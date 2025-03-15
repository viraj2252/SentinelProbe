"""Scanner service for the Reconnaissance module."""

import asyncio
import socket
from typing import Dict, List, Optional, Tuple

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


class PortScannerService:
    """Service for port scanning operations."""

    def __init__(
        self,
        target_repository: TargetRepository,
        port_repository: PortRepository,
        service_repository: ServiceRepository,
    ):
        """Initialize with repositories."""
        self.target_repository = target_repository
        self.port_repository = port_repository
        self.service_repository = service_repository
        # Default common ports to scan
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy",
        }

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address.

        Args:
            hostname: Target hostname

        Returns:
            Optional[str]: IP address or None if resolution fails
        """
        try:
            # Use socket.getaddrinfo to support both IPv4 and IPv6
            addr_info = await asyncio.to_thread(
                socket.getaddrinfo, hostname, None, socket.AF_INET
            )
            if addr_info:
                # Extract the first IPv4 address
                return addr_info[0][4][0]
            return None
        except socket.gaierror:
            return None

    async def scan_port(
        self, target_ip: str, port: int, timeout: float = 1.0
    ) -> Tuple[int, PortStatus]:
        """
        Scan a specific port on the target.

        Args:
            target_ip: Target IP address
            port: Port number to scan
            timeout: Connection timeout in seconds

        Returns:
            Tuple[int, PortStatus]: Port number and status
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Attempt connection
            result = await asyncio.to_thread(sock.connect_ex, (target_ip, port))

            sock.close()

            # Check if port is open
            if result == 0:
                return port, PortStatus.OPEN
            else:
                return port, PortStatus.CLOSED

        except (socket.timeout, ConnectionRefusedError):
            return port, PortStatus.FILTERED
        except Exception:
            return port, PortStatus.CLOSED

    async def detect_service(
        self, target_ip: str, port: int, protocol: str
    ) -> Optional[Dict]:
        """
        Attempt to detect the service running on an open port.

        Args:
            target_ip: Target IP address
            port: Port number
            protocol: Protocol (e.g., 'tcp')

        Returns:
            Optional[Dict]: Service information or None if detection fails
        """
        # Simple service detection based on common ports
        if port in self.common_ports:
            service_name = self.common_ports[port]

            # Determine service type based on name
            service_type = ServiceType.OTHER

            if "HTTP" in service_name:
                service_type = ServiceType.HTTP
            elif "HTTPS" in service_name:
                service_type = ServiceType.HTTPS
            elif "SSH" in service_name:
                service_type = ServiceType.SSH
            elif "FTP" in service_name:
                service_type = ServiceType.FTP
            elif "SMTP" in service_name:
                service_type = ServiceType.SMTP
            elif "DNS" in service_name:
                service_type = ServiceType.DNS

            return {
                "name": service_name,
                "service_type": service_type,
                "version": None,
                "banner": None,
            }

        return None

    async def scan_target(
        self, target_id: int, ports: Optional[List[int]] = None
    ) -> Target:
        """
        Scan a target for open ports and services.

        Args:
            target_id: Target ID
            ports: List of ports to scan (optional, defaults to common ports)

        Returns:
            Target: Updated target with scan results
        """
        # Get target
        target = await self.target_repository.get_target(target_id)
        if not target:
            raise ValueError(f"Target with ID {target_id} not found")

        # Update target status to scanning
        target = await self.target_repository.update_target(
            target_id=target_id,
            status=TargetStatus.SCANNING,
        )
        assert target is not None, "Target was found previously but is now None"

        # Resolve hostname if IP address is not set
        if not target.ip_address:
            ip_address = await self.resolve_hostname(target.hostname)
            if not ip_address:
                # Update target status to failed if resolution fails
                result = await self.target_repository.update_target(
                    target_id=target_id,
                    status=TargetStatus.FAILED,
                    metadata={
                        **target.target_metadata,
                        "error": "Failed to resolve hostname",
                    },
                )
                assert result is not None, "Target was found previously but is now None"
                return result

            # Update target with resolved IP address
            target = await self.target_repository.update_target(
                target_id=target_id,
                ip_address=ip_address,
            )
            assert target is not None, "Target was found previously but is now None"

        # Use provided ports or default to common ports
        ports_to_scan = ports if ports else list(self.common_ports.keys())

        # Ensure target has an IP address
        if not target.ip_address:
            # Update target status to failed if IP address is missing
            result = await self.target_repository.update_target(
                target_id=target_id,
                status=TargetStatus.FAILED,
                metadata={**target.target_metadata, "error": "Missing IP address"},
            )
            assert result is not None, "Target was found previously but is now None"
            return result

        # Scan ports concurrently
        scan_tasks = [self.scan_port(target.ip_address, port) for port in ports_to_scan]

        # Gather results
        port_results = await asyncio.gather(*scan_tasks)

        # Process results
        open_ports_count = 0
        for port_number, status in port_results:
            # Skip creating records for closed ports to save database space
            if status == PortStatus.CLOSED:
                continue

            # Create port record
            port = await self.port_repository.create_port(
                target_id=target_id,
                port_number=port_number,
                protocol="tcp",
                status=status,
            )

            open_ports_count += 1

            # If port is open, attempt service detection
            if status == PortStatus.OPEN and target.ip_address:
                service_info = await self.detect_service(
                    target.ip_address, port_number, "tcp"
                )

                if service_info:
                    # Create service record
                    await self.service_repository.create_service(
                        port_id=port.id,
                        service_type=service_info["service_type"],
                        name=service_info["name"],
                        version=service_info["version"],
                        banner=service_info["banner"],
                    )

        # Update target status to completed
        scan_metadata = {
            **target.target_metadata,
            "total_ports_scanned": len(ports_to_scan),
            "open_ports_found": open_ports_count,
        }

        result = await self.target_repository.update_target(
            target_id=target_id,
            status=TargetStatus.COMPLETED,
            metadata=scan_metadata,
        )
        assert result is not None, "Target was found previously but is now None"
        return result
