"""Scanner module for the Reconnaissance package."""

import asyncio
import ipaddress
import logging
import random
import socket
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

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
from sentinelprobe.reconnaissance.service_detector import ServiceDetector

logger = logging.getLogger(__name__)


class ScanMode(str, Enum):
    """Scan mode for the port scanner."""

    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"


class PortScannerService:
    """Service for port scanning operations."""

    def __init__(
        self,
        target_repository: TargetRepository,
        port_repository: PortRepository,
        service_repository: ServiceRepository,
        scan_rate: float = 0.5,  # Ports per second
        jitter: float = 0.2,  # Random jitter to add to scan timing
        max_concurrent_scans: int = 10,  # Max concurrent port scans
        timeout: float = 1.0,  # Default socket timeout in seconds
        aggressive_mode: bool = False,  # Whether to use aggressive scanning
    ):
        """Initialize with repositories and scan parameters.

        Args:
            target_repository: Repository for Target operations
            port_repository: Repository for Port operations
            service_repository: Repository for Service operations
            scan_rate: The number of ports to scan per second (default: 0.5).
            jitter: Random jitter to add to scan timing (default: 0.2).
            max_concurrent_scans: Maximum number of concurrent port scans (default: 10).
            timeout: Default socket timeout in seconds (default: 1.0).
            aggressive_mode: Whether to use aggressive scanning (default: False).
        """
        self.target_repository = target_repository
        self.port_repository = port_repository
        self.service_repository = service_repository

        # Configure scan timing parameters
        self.scan_rate = scan_rate
        self.jitter = jitter
        self.max_concurrent_scans = max_concurrent_scans
        self.timeout = timeout
        self.aggressive_mode = aggressive_mode

        # Initialize service detector with scan timeout
        self.service_detector = ServiceDetector(timeout=timeout)

        # Default common ports to scan
        self.common_ports: Dict[int, Dict[str, Union[str, ServiceType]]] = {
            21: {"service_type": ServiceType.FTP, "name": "FTP"},
            22: {"service_type": ServiceType.SSH, "name": "SSH"},
            23: {"service_type": ServiceType.TELNET, "name": "Telnet"},
            25: {"service_type": ServiceType.SMTP, "name": "SMTP"},
            53: {"service_type": ServiceType.DNS, "name": "DNS"},
            80: {"service_type": ServiceType.HTTP, "name": "HTTP"},
            110: {"service_type": ServiceType.POP3, "name": "POP3"},
            111: {"service_type": ServiceType.RPC, "name": "RPC"},
            123: {"service_type": ServiceType.NTP, "name": "NTP"},
            135: {"service_type": ServiceType.MSRPC, "name": "MS-RPC"},
            139: {"service_type": ServiceType.NETBIOS, "name": "NetBIOS"},
            143: {"service_type": ServiceType.IMAP, "name": "IMAP"},
            161: {"service_type": ServiceType.SNMP, "name": "SNMP"},
            389: {"service_type": ServiceType.LDAP, "name": "LDAP"},
            443: {"service_type": ServiceType.HTTPS, "name": "HTTPS"},
            445: {"service_type": ServiceType.SMB, "name": "SMB"},
            465: {"service_type": ServiceType.SMTPS, "name": "SMTPS"},
            587: {"service_type": ServiceType.SMTP, "name": "SMTP Submission"},
            631: {"service_type": ServiceType.IPP, "name": "IPP"},
            993: {"service_type": ServiceType.IMAPS, "name": "IMAPS"},
            995: {"service_type": ServiceType.POP3S, "name": "POP3S"},
            1433: {"service_type": ServiceType.MSSQL, "name": "MS-SQL"},
            1521: {"service_type": ServiceType.ORACLE, "name": "Oracle"},
            1723: {"service_type": ServiceType.PPTP, "name": "PPTP"},
            3306: {"service_type": ServiceType.MYSQL, "name": "MySQL"},
            3389: {"service_type": ServiceType.RDP, "name": "RDP"},
            5432: {"service_type": ServiceType.POSTGRESQL, "name": "PostgreSQL"},
            5900: {"service_type": ServiceType.VNC, "name": "VNC"},
            5901: {"service_type": ServiceType.VNC, "name": "VNC-1"},
            5902: {"service_type": ServiceType.VNC, "name": "VNC-2"},
            6379: {"service_type": ServiceType.REDIS, "name": "Redis"},
            8080: {"service_type": ServiceType.HTTP_PROXY, "name": "HTTP Proxy"},
            8443: {"service_type": ServiceType.HTTPS, "name": "HTTPS Alt"},
            9000: {"service_type": ServiceType.HTTP, "name": "HTTP Alt"},
            9200: {"service_type": ServiceType.ELASTICSEARCH, "name": "Elasticsearch"},
            9418: {"service_type": ServiceType.GIT, "name": "Git"},
            27017: {"service_type": ServiceType.MONGODB, "name": "MongoDB"},
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
            # Check if the hostname is already an IP address
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            # Hostname is not an IP address, try to resolve it
            try:
                # Resolve using socket.getaddrinfo to get the IP address
                info = await asyncio.to_thread(
                    socket.getaddrinfo,
                    hostname,
                    None,
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                )
                # Extract the first IP address from the result
                return str(info[0][4][0])
            except (socket.gaierror, IndexError):
                # Could not resolve hostname
                logger.warning(f"Failed to resolve hostname {hostname}")
                return None

    async def scan_port(
        self, ip_address: str, port: int, timeout: Optional[float] = None
    ) -> Tuple[int, PortStatus]:
        """
        Scan a specific port on the target.

        Args:
            ip_address: Target IP address
            port: Port number to scan
            timeout: Connection timeout in seconds (optional)

        Returns:
            Tuple[int, PortStatus]: Port number and status
        """
        if timeout is None:
            timeout = self.timeout

        if ip_address is None:
            logger.error(f"Cannot scan port {port}: IP address is None")
            return port, PortStatus.CLOSED

        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Attempt connection
            result = await asyncio.to_thread(sock.connect_ex, (ip_address, port))

            sock.close()

            # Check if port is open
            if result == 0:
                logger.info(f"Port {port} is open on {ip_address}")
                return port, PortStatus.OPEN
            else:
                return port, PortStatus.CLOSED

        except (socket.timeout, ConnectionRefusedError):
            return port, PortStatus.FILTERED
        except Exception:
            return port, PortStatus.CLOSED

    async def detect_service(
        self, ip_address: str, port: int, protocol: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to detect the service running on an open port.

        Args:
            ip_address: Target IP address
            port: Port number
            protocol: Protocol (e.g., 'tcp')

        Returns:
            Optional[Dict]: Service information or None if detection fails
        """
        if ip_address is None:
            logger.error(f"Cannot detect service on port {port}: IP address is None")
            return {
                "service_type": ServiceType.UNKNOWN,
                "name": "Unknown",
                "version": "",
                "banner": "",
            }

        # First, try the advanced service detection
        try:
            service_info = await self.service_detector.detect_service(
                ip_address, port, protocol
            )
            if service_info and service_info.get("service_type") != ServiceType.UNKNOWN:
                service_name = service_info.get("name")
                service_version = service_info.get("version")
                logger.info(
                    f"Service detected on {ip_address}:{port} - "
                    f"{service_name} {service_version}"
                )
                return service_info
        except Exception as e:
            logger.error(
                f"Error in advanced service detection for {ip_address}:{port}: "
                f"{str(e)}"
            )

        # Fall back to basic port mapping if advanced detection fails
        if port in self.common_ports:
            port_name = self.common_ports[port].get("name")
            logger.info(
                f"Using common port mapping for {ip_address}:{port} - {port_name}"
            )
            return self.common_ports[port]

        # If all else fails, return unknown service
        logger.info(f"Unknown service on {ip_address}:{port}")
        return {
            "service_type": ServiceType.UNKNOWN,
            "name": "Unknown",
            "version": "",
            "banner": "",
        }

    async def scan_target(
        self,
        target_id: int,
        ports: Optional[List[int]] = None,
        scan_rate: Optional[float] = None,
        jitter: Optional[float] = None,
        max_concurrent_scans: Optional[int] = None,
        aggressive_mode: Optional[bool] = None,
    ) -> Optional[Target]:
        """Scan a target for open ports.

        Args:
            target_id: The ID of the target to scan.
            ports: The ports to scan. If None, scan common ports.
            scan_rate: Override the default scan rate (ports per second).
            jitter: Override the default jitter value.
            max_concurrent_scans: Override the max concurrent scans.
            aggressive_mode: Override the aggressive mode setting.

        Returns:
            The updated target object, or None if the target was not found.
        """
        # Use instance defaults if not provided
        scan_rate = scan_rate if scan_rate is not None else self.scan_rate
        jitter = jitter if jitter is not None else self.jitter
        max_concurrent_scans = (
            max_concurrent_scans
            if max_concurrent_scans is not None
            else self.max_concurrent_scans
        )
        aggressive_mode = (
            aggressive_mode if aggressive_mode is not None else self.aggressive_mode
        )

        target = await self.target_repository.get_target(target_id)
        if not target:
            logger.error(f"Target {target_id} not found")
            return None

        scan_started_at = datetime.now().isoformat()

        # Update target metadata with scan parameters
        target_metadata = target.target_metadata or {}
        target_metadata.update(
            {
                "scan_started_at": scan_started_at,
                "scan_rate": scan_rate,
                "max_concurrent_scans": max_concurrent_scans,
                "aggressive_mode": aggressive_mode,
            }
        )

        # Update target status to scanning
        target = await self.target_repository.update_target(
            target_id,
            status=TargetStatus.SCANNING,
            metadata=target_metadata,
        )

        if not target:
            logger.error(f"Failed to update target {target_id}")
            return None

        # Resolve hostname to IP address if needed
        ip_address = target.ip_address
        if not ip_address:
            ip_address = await self.resolve_hostname(target.hostname)
            if not ip_address:
                logger.error(f"Failed to resolve hostname {target.hostname}")
                target = await self.target_repository.update_target(
                    target_id,
                    status=TargetStatus.FAILED,
                    metadata={
                        **target_metadata,
                        "error": f"Failed to resolve hostname {target.hostname}",
                        "scan_completed_at": datetime.now().isoformat(),
                    },
                )
                return target

            # Update target with resolved IP address
            target = await self.target_repository.update_target(
                target_id,
                ip_address=ip_address,
                metadata=target_metadata,
            )
            if not target:
                logger.error(f"Failed to update target {target_id} with IP address")
                return None

        # Determine which ports to scan
        ports_to_scan = ports or list(self.common_ports.keys())
        total_ports = len(ports_to_scan)

        # Update target with total ports to scan
        target_metadata["total_ports_scanned"] = total_ports
        await self.target_repository.update_target(
            target_id,
            metadata=target_metadata,
        )

        open_ports = 0

        if aggressive_mode:
            # In aggressive mode, scan all ports concurrently
            logger.info(f"Aggressive scanning of {total_ports} ports on {ip_address}")
            tasks = [self.scan_port(ip_address, port) for port in ports_to_scan]
            results = await asyncio.gather(*tasks)
        else:
            # In stealth mode, scan ports in batches with rate limiting
            logger.info(
                f"Stealth scanning of {total_ports} ports on {ip_address} "
                f"with rate {scan_rate} ports/sec"
            )
            results = []
            for i in range(0, total_ports, max_concurrent_scans):
                batch = ports_to_scan[i : i + max_concurrent_scans]
                tasks = [self.scan_port(ip_address, port) for port in batch]
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)

                # Calculate delay based on scan_rate and add jitter
                if i + max_concurrent_scans < total_ports:
                    base_delay = len(batch) / scan_rate if scan_rate > 0 else 0
                    if base_delay > 0:
                        # Add random jitter
                        jitter_value = random.uniform(-jitter, jitter) * base_delay
                        delay = max(0, base_delay + jitter_value)
                        logger.debug(f"Delaying {delay:.2f}s between batches")
                        await asyncio.sleep(delay)

        # Process the scan results
        for port, status in results:
            # Only create records for open ports to save space
            if status in [PortStatus.OPEN, PortStatus.FILTERED]:
                port_obj = await self.port_repository.create_port(
                    target_id=target_id,
                    port_number=port,
                    protocol="tcp",
                    status=status,
                )

                if status == PortStatus.OPEN:
                    open_ports += 1

                    # Use the new enhanced service detection
                    service_info = await self.detect_service(ip_address, port, "tcp")
                    if service_info:
                        # Add additional metadata for the service
                        service_metadata = {}

                        # Include banner in metadata if available
                        if "banner" in service_info and service_info["banner"]:
                            service_metadata["raw_banner"] = service_info["banner"]

                        # Create the service record
                        await self.service_repository.create_service(
                            port_id=port_obj.id,
                            service_type=service_info.get(
                                "service_type", ServiceType.UNKNOWN
                            ),
                            name=service_info.get("name", "Unknown"),
                            version=service_info.get("version", ""),
                            banner=service_info.get("banner", ""),
                            metadata=service_metadata,
                        )

        # Update target with final metadata
        target_metadata.update(
            {
                "open_ports_found": open_ports,
                "scan_completed_at": datetime.now().isoformat(),
            }
        )

        target = await self.target_repository.update_target(
            target_id,
            status=TargetStatus.COMPLETED,
            metadata=target_metadata,
        )

        return target
