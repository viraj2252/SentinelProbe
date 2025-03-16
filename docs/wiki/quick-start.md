# Quick Start Guide

This guide will help you quickly set up SentinelProbe and run your first penetration test scan.

## Prerequisites

Before you begin, ensure you have:

- Python 3.10 or higher
- Docker and Docker Compose (for the simplest setup)
- A target system to scan (we'll use a test virtual machine in this example)
- 8GB+ RAM and 4+ CPU cores recommended

## Step 1: Installation

The fastest way to get started is using Docker:

```bash
# Clone the repository
git clone https://github.com/viraj2252/sentinelprobe.git
cd sentinelprobe

# Start the containers
docker-compose up -d
```

If you prefer a manual installation:

```bash
# Clone the repository
git clone https://github.com/viraj2252/sentinelprobe.git
cd sentinelprobe

# Set up Python environment
poetry install
poetry shell

# Configure the environment
cp .env.example .env
nano .env  # Edit with your settings

# Run the service
python -m sentinelprobe run
```

## Step 2: Configure a Test Target

For this quick start, we'll set up a safe target to scan.

> ⚠️ **WARNING**: Only scan systems you have explicit permission to test. Unauthorized scanning is illegal in most jurisdictions.

### Option 1: Use a Test VM

1. Create a test virtual machine (e.g., using VirtualBox)
2. Install a vulnerable system like Metasploitable or DVWA
3. Ensure the VM is on a private network

### Option 2: Use Docker-based Targets

```bash
# Pull and run a deliberately vulnerable container for testing
docker run -d --name vulnerable-test-system -p 8080:80 vulnerables/web-dvwa
```

## Step 3: Create Your First Scan Job

### Using the Web Interface (if implemented)

1. Navigate to `http://localhost:8080` in your browser
2. Log in with the default credentials (`admin`/`sentinelprobe`)
3. Click "New Scan" and follow the wizard

### Using the CLI

```bash
# Inside the poetry shell (if not using Docker)
python -m sentinelprobe job create --target 192.168.56.101 --name "First Scan" --scan-type comprehensive

# If using Docker
docker exec -it sentinelprobe python -m sentinelprobe job create --target 192.168.56.101 --name "First Scan" --scan-type comprehensive
```

### Using the API

```bash
# Create a job via API
curl -X POST http://localhost:8000/api/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "name": "First Scan",
    "target": {
      "host": "192.168.56.101",
      "description": "Test VM"
    },
    "scan_type": "comprehensive",
    "options": {
      "reconnaissance": {"port_scan_range": "1-1000"},
      "vulnerability_scan": {"enabled": true},
      "exploitation": {"enabled": false}
    }
  }'
```

## Step 4: Monitor Scan Progress

### Using the Web Interface

1. Navigate to the "Jobs" section
2. Click on your job to see real-time progress

### Using the CLI

```bash
# Get job status
python -m sentinelprobe job status --id 1

# View job logs
python -m sentinelprobe job logs --id 1 --follow
```

### Using the API

```bash
# Get job status
curl http://localhost:8000/api/jobs/1

# Get reconnaissance results
curl http://localhost:8000/api/jobs/1/reconnaissance
```

## Step 5: Review Results

Once the scan completes (which may take a few minutes to an hour depending on scope), you can review the results.

### Using the Web Interface

1. Navigate to the "Reports" section
2. Click on your job to see the comprehensive report
3. Explore the findings by category, severity, and exploitability

### Using the CLI

```bash
# Generate a report
python -m sentinelprobe report generate --job-id 1 --format pdf

# Display summary
python -m sentinelprobe report summary --job-id 1
```

### Using the API

```bash
# Get full report
curl http://localhost:8000/api/jobs/1/report

# Get vulnerabilities
curl http://localhost:8000/api/jobs/1/vulnerabilities
```

## Step 6: Understand the Results

The scan results will include several key sections:

1. **Reconnaissance Summary**:
   - Discovered services and ports
   - Operating system details
   - Network topology

2. **Vulnerabilities**:
   - Identified vulnerabilities with severity ratings
   - Potential impact descriptions
   - Technical details and evidence

3. **Exploitation Results** (if enabled):
   - Successful exploit attempts
   - Post-exploitation findings
   - Privilege escalation paths

4. **Remediation Recommendations**:
   - Prioritized remediation steps
   - Configuration fixes
   - Patch recommendations

## Step 7: Configure a Custom Scan

For more targeted testing, you can customize your scan parameters:

### Using Configuration Files

```yaml
# custom-scan.yaml
job:
  name: "Custom Web App Scan"
  target:
    host: "192.168.56.101"
    description: "Web Application Server"

  options:
    reconnaissance:
      port_scan_type: "targeted"
      port_scan_range: "80,443,8080-8090"

    vulnerability_scan:
      enabled: true
      scanners:
        - "web_app"
        - "ssl_tls"
      depth: "comprehensive"

    exploitation:
      enabled: true
      safe_exploits_only: true

    ai_decision:
      rules:
        - "web_application_default"
        - "sql_injection_focus"
```

Then run the scan with your custom configuration:

```bash
python -m sentinelprobe job create --config custom-scan.yaml
```

## Next Steps

Now that you've completed your first scan, here are some next steps:

1. Learn about [Custom Rule Development](advanced/custom-rules.md)
2. Explore the [AI Decision Engine](components/ai-decision-engine.md)
3. Set up [Continuous Security Testing](advanced/continuous-testing.md)
4. Integrate with your [CI/CD Pipeline](advanced/integration.md)

## Troubleshooting

### Common Issues

#### Scan Not Starting

```bash
# Check system status
python -m sentinelprobe status

# View the logs
tail -f logs/sentinelprobe.log
```

#### Connection Errors

Ensure:

- Target is reachable (try `ping <target>`)
- Firewall rules allow scanning traffic
- You have proper permissions

#### Resource Issues

SentinelProbe can be resource-intensive. If experiencing issues:

```bash
# Check resource usage
docker stats  # If using Docker

# Limit scan scope
python -m sentinelprobe job create --target 192.168.56.101 --name "Lightweight Scan" --scan-type basic
```

For more help, see the [Troubleshooting Guide](troubleshooting.md).
