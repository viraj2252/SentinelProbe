"""Service detection module for the Reconnaissance package."""

import asyncio
import logging
import re
import socket
from typing import Dict, List, Optional, Tuple, Union

from sentinelprobe.reconnaissance.models import ServiceType

logger = logging.getLogger(__name__)

# Dictionary of service detection patterns
# Format: {regex_pattern: (service_type, service_name)}
SERVICE_PATTERNS = {
    # HTTP/HTTPS patterns
    r"^HTTP/\d": (ServiceType.HTTP, "HTTP"),
    r"(?i)^GET|^POST|^HTTP": (ServiceType.HTTP, "HTTP-like"),
    # SSH patterns
    r"^SSH-\d": (ServiceType.SSH, "SSH"),
    # FTP patterns
    r"^220.*FTP": (ServiceType.FTP, "FTP"),
    # SMTP patterns
    r"^220.*SMTP": (ServiceType.SMTP, "SMTP"),
    r"^220.*mail": (ServiceType.SMTP, "SMTP"),
    # MySQL patterns
    r"^\x5b\x00\x00\x00\x0a": (ServiceType.MYSQL, "MySQL"),
    # MSSQL patterns
    r"\x04\x01\x00": (ServiceType.MSSQL, "Microsoft SQL Server"),
    # Redis patterns
    r"-ERR unknown command": (ServiceType.REDIS, "Redis"),
    r"\+PONG": (ServiceType.REDIS, "Redis"),
    # PostgreSQL patterns
    r"PGRES": (ServiceType.POSTGRESQL, "PostgreSQL"),
    # MongoDB patterns
    r"MongoDB": (ServiceType.MONGODB, "MongoDB"),
    # Elasticsearch patterns
    r'"cluster_name"\s*:': (ServiceType.ELASTICSEARCH, "Elasticsearch"),
    # Telnet patterns
    r"^\xff\xfb\x01\xff\xfb\x03": (ServiceType.TELNET, "Telnet"),
    # IMAP patterns
    r"^\* OK.*IMAP": (ServiceType.IMAP, "IMAP"),
    # POP3 patterns
    r"^\+OK.*POP3": (ServiceType.POP3, "POP3"),
    # DNS patterns
    r"^\x00\x00\x10\x00\x00": (ServiceType.DNS, "DNS"),
    # LDAP patterns
    r"^\x30\x0c\x02\x01\x01\x60": (ServiceType.LDAP, "LDAP"),
    # RDP patterns
    r"^\x03\x00\x00\x13": (ServiceType.RDP, "RDP"),
    # VNC patterns
    r"^RFB \d": (ServiceType.VNC, "VNC"),
    # NTP patterns
    r"^[^\x00-\x19]NTP": (ServiceType.NTP, "NTP"),
}

# Version detection patterns
# Format: {service_type: [(version_regex, sub_expression_index)]}
VERSION_PATTERNS = {
    ServiceType.HTTP: [
        (r"Server: ([^\r\n]+)", 0),  # Extract Server header
        (r"X-Powered-By: ([^\r\n]+)", 0),  # Extract X-Powered-By header
    ],
    ServiceType.SSH: [
        (r"SSH-\d+\.\d+-([\w.-]+)", 0),  # Extract SSH version
    ],
    ServiceType.FTP: [
        (r"220[- ]([^\r\n]+)", 0),  # Extract FTP banner version
    ],
    ServiceType.SMTP: [
        (r"220 [^(]*\(([^)]+)\)", 0),  # Extract version from parentheses
        (r"220[- ]([^\r\n]+)", 0),  # Extract SMTP banner
    ],
    ServiceType.MYSQL: [
        (r"(\d+\.\d+\.\d+)", 0),  # Extract MySQL version
    ],
    ServiceType.POSTGRESQL: [
        (r"PostgreSQL (\d+\.\d+\.\d+)", 0),  # Extract PostgreSQL version
    ],
}

# Protocol probes
# Format: service_type: (probe_data, timeout)
PROTOCOL_PROBES = {
    ServiceType.HTTP: (b"GET / HTTP/1.0\r\n\r\n", 3.0),
    ServiceType.HTTPS: (b"", 3.0),  # Just connect for HTTPS
    ServiceType.FTP: (b"", 3.0),  # Just connect for FTP
    ServiceType.SSH: (b"", 3.0),  # Just connect for SSH
    ServiceType.SMTP: (b"EHLO example.com\r\n", 3.0),
    ServiceType.POP3: (b"", 3.0),  # Just connect for POP3
    ServiceType.IMAP: (b"a001 CAPABILITY\r\n", 3.0),
    ServiceType.MYSQL: (b"", 3.0),  # Just connect for MySQL
    ServiceType.MSSQL: (b"", 3.0),  # Just connect for MSSQL
    ServiceType.REDIS: (b"PING\r\n", 3.0),
    ServiceType.POSTGRESQL: (b"", 3.0),  # Just connect for PostgreSQL
    ServiceType.MONGODB: (b"", 3.0),  # Just connect for MongoDB
    ServiceType.ELASTICSEARCH: (b"GET / HTTP/1.0\r\n\r\n", 3.0),
    ServiceType.DNS: (
        # DNS query for www.example.com
        b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x03www\x07example\x03com\x00\x00\x01\x00\x01",
        3.0,
    ),
    ServiceType.LDAP: (b"0\x0c\x02\x01\x01`\x07\x02\x01\x02\x04\x00\x80\x00", 3.0),
    ServiceType.RDP: (
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        3.0,
    ),
    ServiceType.VNC: (b"RFB 003.008\n", 3.0),
}


class ServiceDetector:
    """Service detector for advanced service fingerprinting."""

    def __init__(self, timeout: float = 3.0):
        """Initialize with timeout in seconds.

        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout

    async def grab_banner(
        self, ip_address: str, port: int, timeout: Optional[float] = None
    ) -> str:
        """
        Attempt to grab a service banner from the specified port.

        Args:
            ip_address: Target IP address
            port: Target port number
            timeout: Connection timeout in seconds, defaults to instance timeout

        Returns:
            Service banner as string, or empty string if unsuccessful
        """
        if timeout is None:
            timeout = self.timeout

        if ip_address is None:
            logger.debug(f"Cannot grab banner for port {port}: IP address is None")
            return ""

        try:
            # Create socket and set timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Connect to the target
            await asyncio.to_thread(sock.connect, (ip_address, port))

            # Some services send a banner immediately upon connection
            try:
                banner = await asyncio.to_thread(sock.recv, 1024)
                banner_text = banner.decode("utf-8", errors="ignore")
            except (socket.timeout, ConnectionResetError):
                banner_text = ""

            # Close the socket
            sock.close()
            return banner_text

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Banner grab failed for {ip_address}:{port} - {str(e)}")
            return ""

    async def probe_service(
        self,
        ip_address: str,
        port: int,
        probe_data: bytes,
        timeout: Optional[float] = None,
    ) -> str:
        """
        Send a probe to a service and get the response.

        Args:
            ip_address: Target IP address
            port: Target port number
            probe_data: Data to send as a probe
            timeout: Connection timeout in seconds, defaults to instance timeout

        Returns:
            Service response as string, or empty string if unsuccessful
        """
        if timeout is None:
            timeout = self.timeout

        try:
            # Create socket and set timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Connect to the target
            await asyncio.to_thread(sock.connect, (ip_address, port))

            # Send probe data if provided
            if probe_data:
                await asyncio.to_thread(sock.sendall, probe_data)

            # Receive response
            try:
                response = await asyncio.to_thread(sock.recv, 2048)
                response_text = response.decode("utf-8", errors="ignore")
            except (socket.timeout, ConnectionResetError):
                response_text = ""

            # Close the socket
            sock.close()
            return response_text

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Service probe failed for {ip_address}:{port} - {str(e)}")
            return ""

    def identify_service_type(self, banner: str) -> Tuple[ServiceType, str]:
        """
        Identify the service type from a banner using regex patterns.

        Args:
            banner: Service banner text

        Returns:
            Tuple of (ServiceType, service_name)
        """
        for pattern, (service_type, service_name) in SERVICE_PATTERNS.items():
            if re.search(pattern, banner, re.MULTILINE):
                return service_type, service_name

        return ServiceType.UNKNOWN, "Unknown"

    def extract_version(self, banner: str, service_type: ServiceType) -> str:
        """
        Extract version information from a banner based on service type.

        Args:
            banner: Service banner text
            service_type: Type of service to extract version for

        Returns:
            Version string or empty string if not found
        """
        if service_type in VERSION_PATTERNS:
            for pattern, sub_idx in VERSION_PATTERNS[service_type]:
                match = re.search(pattern, banner, re.MULTILINE)
                if match:
                    try:
                        return match.group(1).strip()
                    except IndexError:
                        pass

        return ""

    async def detect_service(
        self, ip_address: str, port: int, protocol: str = "tcp"
    ) -> Dict[str, Union[str, ServiceType, int]]:
        """
        Perform comprehensive service detection including type, name, and version.

        Args:
            ip_address: Target IP address
            port: Target port number
            protocol: Network protocol (e.g., 'tcp')

        Returns:
            Dictionary with service information: service_type, name, version, banner
        """
        if ip_address is None:
            logger.debug(f"Cannot detect service on port {port}: IP address is None")
            return {
                "service_type": ServiceType.UNKNOWN,
                "name": "Unknown",
                "version": "",
                "banner": "",
                "port": port,
                "protocol": protocol,
            }

        result: Dict[str, Union[str, ServiceType, int]] = {
            "service_type": ServiceType.UNKNOWN,
            "name": "Unknown",
            "version": "",
            "banner": "",
        }

        # Step 1: Grab initial banner
        banner = await self.grab_banner(ip_address, port)

        # If we got a banner, try to identify from it
        if banner:
            service_type, service_name = self.identify_service_type(banner)
            result["service_type"] = service_type
            result["name"] = service_name
            result["banner"] = banner
            result["version"] = self.extract_version(banner, service_type)

            # If we already identified with high confidence, return
            if service_type != ServiceType.UNKNOWN and result["version"]:
                return result

        # Step 2: Try protocol-specific probes for better identification
        for probe_service_type, (probe_data, probe_timeout) in PROTOCOL_PROBES.items():
            # Skip if we already have a good identification
            if result["service_type"] != ServiceType.UNKNOWN and result["version"]:
                break

            try:
                probe_response = await self.probe_service(
                    ip_address, port, probe_data, probe_timeout
                )

                if probe_response:
                    # Check if this response helps identify the service
                    identified_type, identified_name = self.identify_service_type(
                        probe_response
                    )

                    # If we got a better identification than before, update
                    if identified_type != ServiceType.UNKNOWN:
                        result["service_type"] = identified_type
                        result["name"] = identified_name

                        # Merge banners for better version detection
                        combined_banner = f"{banner}\n{probe_response}".strip()
                        result["banner"] = combined_banner

                        # Try to extract version from combined banner
                        version = self.extract_version(combined_banner, identified_type)
                        if version:
                            result["version"] = version

            except Exception as e:
                logger.debug(f"Error during probe of {ip_address}:{port} - {str(e)}")
                continue

        # Step 3: Try common banner parsing patterns for version detection
        if not result["version"] and result["banner"]:
            # Generic version patterns that might work across services
            generic_patterns = [
                r"v\d+\.\d+(\.\d+)?",  # matches v1.2.3
                r"version\s+(\d+\.\d+(\.\d+)?)",  # matches "version 1.2.3"
                r"(\d+\.\d+(\.\d+)(-\w+)?)",  # matches 1.2.3 or 1.2.3-alpha
            ]

            for pattern in generic_patterns:
                match = re.search(pattern, str(result["banner"]), re.IGNORECASE)
                if match:
                    result["version"] = match.group(0)
                    break

        result_dict: Dict[str, Union[str, ServiceType, int]] = {
            "service_type": result["service_type"],
            "name": str(result["name"]),
            "version": str(result["version"]),
            "banner": str(result["banner"]),
            "port": port,
            "protocol": str(protocol),
        }
        return result_dict

    async def detect_services_batch(
        self, ip_address: str, ports: List[int], protocol: str = "tcp"
    ) -> Dict[int, Dict[str, Union[str, ServiceType, int]]]:
        """
        Perform service detection on multiple ports.

        Args:
            ip_address: Target IP address
            ports: List of port numbers to scan
            protocol: Network protocol (e.g., 'tcp')

        Returns:
            Dictionary mapping port numbers to service information
        """
        tasks = [self.detect_service(ip_address, port, protocol) for port in ports]
        results = await asyncio.gather(*tasks)

        return dict(zip(ports, results))
