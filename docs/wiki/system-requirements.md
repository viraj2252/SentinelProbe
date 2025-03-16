# System Requirements

This document outlines the minimum and recommended system requirements for running SentinelProbe effectively.

## Hardware Requirements

### Minimum Requirements

- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 20GB free disk space
- **Network**: 100 Mbps Ethernet connection

### Recommended Requirements

- **CPU**: 8+ cores
- **RAM**: 16GB or more
- **Storage**: 50GB+ SSD storage
- **Network**: 1 Gbps Ethernet connection

### High-Performance Setup (for large-scale scanning)

- **CPU**: 16+ cores
- **RAM**: 32GB+
- **Storage**: 100GB+ NVMe SSD
- **Network**: 10 Gbps network interface
- **Distributed Setup**: Multiple worker nodes for concurrent scanning

## Software Requirements

### Operating System

SentinelProbe is compatible with the following operating systems:

- Ubuntu 20.04 LTS or newer
- Debian 11 or newer
- CentOS 8 or newer / Rocky Linux 8+
- macOS 11 (Big Sur) or newer (development only)
- Windows 10/11 with WSL2 (limited functionality)

### Required Software

- **Python**: 3.10 or higher
- **Docker**: 20.10 or newer (for containerized deployment)
- **Docker Compose**: 2.0 or newer
- **Git**: 2.30 or newer
- **PostgreSQL**: 13+ (for production deployments)
- **MongoDB**: 5.0+ (for production deployments)
- **Redis**: 6.2+ (optional, for caching and performance optimization)

### Optional Software

- **Kubernetes**: 1.23+ (for large-scale deployments)
- **Nginx**: 1.20+ (for reverse proxy)
- **Let's Encrypt/Certbot**: For SSL certificates

## Network Requirements

### Outbound Connectivity

SentinelProbe requires outbound access to:

- Target systems on specified ports
- Internet connectivity for threat intelligence updates (optional)
- Package repositories (for updates)

### Inbound Connectivity

If running the web interface:

- TCP port 8000 (default API port)
- TCP port 8080 (default web interface port)
- TCP port 443 (if using HTTPS)

### Firewall Considerations

- Allow outbound connections to target systems
- Allow inbound connections to the web interface (if needed)
- Consider network isolation for exploitation modules

## Permission Requirements

### User Permissions

SentinelProbe requires:

- A dedicated user account (non-root)
- Sudo/administrative privileges for initial setup
- Ability to create and bind to network sockets
- Read/write access to installation directory

### Target System Permissions

To scan target systems, you need:

- **Explicit written permission** to scan and test target systems
- Network access to target systems
- Appropriate credentials (if authenticated scanning is required)

### Security Considerations

- Run SentinelProbe in a dedicated environment
- Use network isolation to prevent unintended scanning
- Implement access controls for the SentinelProbe system
- Follow the principle of least privilege

## Database Requirements

### PostgreSQL

- Version: 13.0 or higher
- RAM: 4GB+ (dedicated)
- Storage: 10GB+ (scales with scan history)
- Extensions: none required

### MongoDB

- Version: 5.0 or higher
- RAM: 4GB+ (dedicated)
- Storage: 10GB+ (scales with scan results)
- WiredTiger storage engine recommended

## Container Requirements

If using Docker-based deployment:

- Docker Engine: 20.10 or newer
- Docker Compose: 2.0 or newer
- Container resources:
  - 4 CPU cores (minimum)
  - 8GB RAM (minimum)
  - 20GB disk space (minimum)

## Cloud Deployment Requirements

For cloud-based deployments:

### AWS

- EC2 instance: t3.large or better (m5.xlarge recommended for production)
- EBS storage: 50GB+ gp3 volume
- Security groups: Configuration for required ports
- IAM: Appropriate permissions for AWS integration (if used)

### Azure

- VM: D4s v3 or better (D8s v3 recommended for production)
- Managed Disks: 50GB+ Premium SSD
- Network security groups: Configuration for required ports

### Google Cloud

- VM: e2-standard-4 or better (n2-standard-8 recommended for production)
- Persistent Disk: 50GB+ SSD
- Firewall rules: Configuration for required ports

## Development Environment Requirements

For development:

- Python 3.10+
- Poetry package manager
- Pre-commit
- Docker and Docker Compose
- IDE with Python support (VS Code, PyCharm, etc.)
- 8GB+ RAM
- Git

## Compatibility

SentinelProbe is compatible with the following tools:

- **Vulnerability Databases**: NVD, CVE
- **Issue Trackers**: Jira, GitHub Issues, GitLab Issues
- **CI/CD Systems**: GitHub Actions, GitLab CI, Jenkins
- **SIEM Systems**: ELK Stack, Splunk (via API)

## Scalability Considerations

For larger deployments:

- Consider a distributed setup with multiple worker nodes
- Set up a dedicated database server
- Implement caching with Redis
- Use load balancing for the API and web interface
- Configure resource limits for scanning operations

## Performance Recommendations

To optimize performance:

- Use SSD storage for databases
- Allocate sufficient RAM for database caching
- Configure connection pooling
- Adjust concurrent scan limits based on hardware
- Implement network QoS for reliable scanning
