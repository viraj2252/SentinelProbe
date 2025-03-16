# Reconnaissance Module

The Reconnaissance Module is a critical component of SentinelProbe that gathers intelligence about target systems to identify potential attack vectors. It serves as the foundation for the entire security testing process by mapping the attack surface of target systems.

## Overview

The primary purpose of the Reconnaissance Module is to discover and catalog targets, open ports, running services, and their versions. This information is then used by subsequent modules to identify vulnerabilities and determine the most efficient testing strategies.

## Key Features

### Network Discovery

- **Target Validation**: Validates IP addresses, hostnames, and CIDR ranges
- **Port Scanning**: Identifies open, closed, and filtered ports on target systems
- **Scan Rate Control**: Configurable scan rates with jitter to avoid detection
- **Scan Modes**: Supports both stealth and aggressive scanning options

### Service Enumeration

- **Service Detection**: Automatically identifies services running on open ports
- **Banner Grabbing**: Collects service banners for fingerprinting purposes
- **Version Detection**: Determines service versions for vulnerability matching
- **Protocol Identification**: Identifies application protocols in use

### Advanced Fingerprinting

- **Advanced Service Fingerprinting**: Uses pattern matching and active probing
- **Operating System Detection**: Attempts to determine target operating system
- **Application Fingerprinting**: Identifies specific applications and versions
- **Evasion Techniques**: Various techniques to avoid detection during reconnaissance

## Architecture

The Reconnaissance Module consists of several key components:

### Scanner

The `PortScannerService` class is responsible for:

- Running port scans against target systems
- Managing scan rates and concurrent connections
- Collecting initial port status information

### Service Detector

The `ServiceDetector` class performs:

- Service identification on open ports
- Version detection using pattern matching
- Protocol analysis for accurate service identification

### Models

Key data models include:

- `Target`: Represents a target system with IP/hostname information
- `Port`: Represents a port on a target with status information
- `Service`: Represents a detected service with version and metadata

### Repository

Database interaction is handled by:

- `TargetRepository`: Manages target system data
- `PortRepository`: Stores port scan results
- `ServiceRepository`: Maintains service detection information

## Configuration Options

The Reconnaissance Module offers several configuration options:

### General Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_rate` | Number of ports to scan per second | 0.5 |
| `jitter` | Random timing variation to avoid detection | 0.2 |
| `max_concurrent_scans` | Maximum concurrent port scans | 10 |
| `timeout` | Socket timeout in seconds | 1.0 |
| `aggressive_mode` | Whether to use aggressive scanning | False |

### Port Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `port_range` | Range of ports to scan (e.g., "1-1024") | "1-1000" |
| `scan_common_ports_only` | Only scan commonly used ports | False |
| `tcp_scan` | Enable TCP scanning | True |
| `udp_scan` | Enable UDP scanning | False |
| `syn_scan` | Use SYN scan technique (requires privileges) | False |

### Service Detection Options

| Option | Description | Default |
|--------|-------------|---------|
| `enable_service_detection` | Enable service detection | True |
| `enable_version_detection` | Attempt to detect service versions | True |
| `service_detection_timeout` | Timeout for service detection in seconds | 3.0 |
| `probe_ssl` | Check if services support SSL/TLS | True |

## Usage Examples

### Programmatic Usage

```python
from sentinelprobe.core.db import get_session
from sentinelprobe.reconnaissance.repository import (
    TargetRepository, PortRepository, ServiceRepository
)
from sentinelprobe.reconnaissance.scanner import PortScannerService
from sentinelprobe.reconnaissance.models import Target

async def run_reconnaissance(ip_address: str):
    """Run reconnaissance on a target IP address."""
    async with get_session() as session:
        # Initialize repositories
        target_repo = TargetRepository(session)
        port_repo = PortRepository(session)
        service_repo = ServiceRepository(session)

        # Initialize scanner with custom parameters
        scanner = PortScannerService(
            target_repository=target_repo,
            port_repository=port_repo,
            service_repository=service_repo,
            scan_rate=1.0,  # Faster scan rate
            max_concurrent_scans=20,  # More concurrent scans
            timeout=2.0  # Longer timeout
        )

        # Create a target
        target = await target_repo.create_target(
            host=ip_address,
            description="Test target",
            job_id=1  # Assuming job ID 1 exists
        )

        # Run port scan
        await scanner.scan_target(
            target_id=target.id,
            port_range="1-1024"
        )

        # Display results
        ports = await port_repo.get_ports_by_target(target.id)
        print(f"Found {len(ports)} open ports")

        services = await service_repo.get_services_by_target(target.id)
        print(f"Identified {len(services)} services")

        # Example: Print service information
        for service in services:
            print(f"Port {service.port}: {service.service_type.value} "
                  f"(Version: {service.version or 'Unknown'})")
```

### API Usage

```python
import aiohttp
import asyncio

async def scan_target_via_api():
    """Scan a target via the SentinelProbe API."""
    async with aiohttp.ClientSession() as session:
        # Create a target
        create_response = await session.post(
            "http://localhost:8000/api/reconnaissance/targets",
            json={
                "host": "192.168.1.100",
                "description": "Web server",
                "job_id": 1
            }
        )
        target_data = await create_response.json()
        target_id = target_data["id"]

        # Start a scan
        scan_response = await session.post(
            f"http://localhost:8000/api/reconnaissance/targets/{target_id}/scan",
            json={
                "port_range": "1-1024",
                "aggressive_mode": False,
                "tcp_scan": True,
                "udp_scan": False
            }
        )

        # Check scan status
        while True:
            status_response = await session.get(
                f"http://localhost:8000/api/reconnaissance/targets/{target_id}"
            )
            status_data = await status_response.json()
            if status_data["status"] in ["completed", "failed"]:
                break
            await asyncio.sleep(5)

        # Get scan results
        ports_response = await session.get(
            f"http://localhost:8000/api/reconnaissance/targets/{target_id}/ports"
        )
        ports_data = await ports_response.json()

        services_response = await session.get(
            f"http://localhost:8000/api/reconnaissance/targets/{target_id}/services"
        )
        services_data = await services_response.json()

        return {
            "target": status_data,
            "ports": ports_data,
            "services": services_data
        }

# Run the async function
loop = asyncio.get_event_loop()
results = loop.run_until_complete(scan_target_via_api())
```

### Command Line Usage

```bash
# Scan a single IP address
python -m sentinelprobe reconnaissance scan --target 192.168.1.100 --job-id 1 --port-range 1-1024

# Scan a CIDR range
python -m sentinelprobe reconnaissance scan --target 192.168.1.0/24 --job-id 1 --common-ports-only

# Run an aggressive scan
python -m sentinelprobe reconnaissance scan --target 10.0.0.1 --job-id 1 --aggressive --timeout 5.0
```

## Integration with AI Decision Engine

The Reconnaissance Module integrates closely with the AI Decision Engine:

1. Scan results are stored in the knowledge base
2. The AI Decision Engine analyzes the results to:
   - Identify high-value targets
   - Determine optimal scanning strategies
   - Prioritize vulnerability scans based on discovered services
   - Adapt scanning parameters for future reconnaissance tasks

## Performance Considerations

To optimize the performance of the Reconnaissance Module:

- **Scan Rate**: Adjust scan rate based on network conditions and detection risk
- **Concurrent Scans**: Increase for faster scanning, decrease for lower detection risk
- **Port Selection**: Scan only relevant ports for faster results
- **Targeting**: Use specific targeting rather than broad network ranges
- **Distributed Scanning**: For large networks, use multiple scanning nodes

## Security and Ethical Considerations

When using the Reconnaissance Module:

- **Obtain Permission**: Always have explicit permission before scanning any system
- **Respect Boundaries**: Stay within the defined scope of the penetration test
- **Minimize Impact**: Use appropriate scan rates to avoid disrupting services
- **Document Activities**: Keep detailed logs of all reconnaissance activities
- **Handle Data Securely**: Treat reconnaissance data as sensitive information

## Future Enhancements

Planned enhancements for the Reconnaissance Module include:

- **Passive Reconnaissance**: DNS enumeration, OSINT integration
- **Web Application Discovery**: Automated discovery of web applications
- **Network Topology Mapping**: Visual representation of network structure
- **Enhanced Evasion Techniques**: Advanced methods to avoid detection
- **Vulnerability Prediction**: Preliminary vulnerability prediction based on service fingerprints

## Troubleshooting

### Common Issues

1. **Slow Scanning**:
   - Increase scan rate and concurrent scans
   - Narrow port range or use common ports only
   - Check network connectivity

2. **False Negatives (Missing Services)**:
   - Increase timeout values
   - Enable aggressive mode
   - Check for firewalls or IDS/IPS systems

3. **Service Misidentification**:
   - Increase service detection timeout
   - Update service detection patterns
   - Use verbose mode to see detection details

## API Reference

For a complete API reference, see the [API Documentation](../advanced/api-reference.md#reconnaissance-module).
