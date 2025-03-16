# Reporting Engine

The Reporting Engine is a critical component of SentinelProbe that transforms raw security assessment data into comprehensive, actionable reports. It aggregates findings from all other modules, analyzes the results, and presents them in a structured format that helps security teams understand and address identified vulnerabilities.

## Overview

The Reporting Engine serves as the final stage in the SentinelProbe workflow, collecting data from the Reconnaissance Module, Vulnerability Scanner, Exploitation Engine, and Post-Exploitation Module. It processes this information to create detailed reports that provide a clear picture of the security posture of the target systems, including vulnerabilities, exploitation paths, and recommended remediation steps.

## Key Features

### Report Generation

- **Multiple Report Types**: Generate full, summary, vulnerability-focused, or reconnaissance-focused reports
- **Flexible Formats**: Output reports in various formats including HTML, PDF, JSON, and plain text
- **Customizable Templates**: Use built-in templates or create custom report templates
- **Executive Summaries**: Automatically generate high-level summaries for management
- **Technical Details**: Include comprehensive technical information for security teams

### Data Aggregation and Analysis

- **Comprehensive Data Collection**: Gather information from all SentinelProbe modules
- **Vulnerability Prioritization**: Rank vulnerabilities based on severity, exploitability, and business impact
- **Attack Path Visualization**: Illustrate potential attack paths through the target environment
- **Trend Analysis**: Track security posture changes over time with multiple assessments
- **Risk Scoring**: Calculate overall risk scores based on findings

### Remediation Guidance

- **Actionable Recommendations**: Provide clear steps to address identified vulnerabilities
- **Prioritized Remediation**: Suggest which issues to fix first based on risk
- **Technical References**: Include links to relevant security resources and documentation
- **Verification Steps**: Outline how to verify that remediation was successful

## Architecture

The Reporting Engine consists of several key components:

### Core Components

- **Reporting Service**: Central service that coordinates report generation
- **Repository Layer**: Data storage and retrieval for reports and templates
- **Rendering Engine**: Converts report data into the requested output format
- **API Layer**: RESTful API for interacting with the Reporting Engine

### Data Models

The Reporting Engine uses several key data models:

- **Report**: Represents a generated report with metadata
- **ReportData**: Contains the actual content and findings for a report
- **VulnerabilityFindings**: Structured representation of vulnerability data
- **ReportTemplate**: Template for generating reports in different formats
- **ReportRequest**: Request parameters for report generation

## Report Types

The Reporting Engine supports various report types to meet different needs:

### Full Report

The Full Report provides comprehensive coverage of all security assessment aspects:

- **Executive Summary**: High-level overview of findings and risk assessment
- **Methodology**: Description of the assessment approach and techniques
- **Reconnaissance Findings**: Discovered assets, services, and network topology
- **Vulnerability Assessment**: Detailed analysis of all identified vulnerabilities
- **Exploitation Results**: Summary of successful and unsuccessful exploitation attempts
- **Post-Exploitation Findings**: Results of privilege escalation and lateral movement
- **Remediation Recommendations**: Prioritized list of remediation steps
- **Appendices**: Technical details, logs, and additional resources

### Summary Report

The Summary Report provides a condensed overview for management and stakeholders:

- **Executive Summary**: Brief overview of the assessment and key findings
- **Risk Assessment**: Overall security posture evaluation
- **Key Findings**: Highlights of the most critical vulnerabilities
- **Remediation Priorities**: Top recommendations for immediate action
- **Conclusion**: Summary of the security assessment results

### Vulnerability Report

The Vulnerability Report focuses specifically on identified vulnerabilities:

- **Vulnerability Summary**: Overview of discovered vulnerabilities by severity
- **Detailed Findings**: In-depth analysis of each vulnerability
- **Affected Systems**: List of systems impacted by each vulnerability
- **Exploitation Potential**: Assessment of how easily vulnerabilities can be exploited
- **Remediation Steps**: Specific actions to address each vulnerability

### Reconnaissance Report

The Reconnaissance Report details the discovered attack surface:

- **Network Topology**: Mapped network structure and relationships
- **Discovered Assets**: Inventory of identified systems and devices
- **Service Enumeration**: List of running services and open ports
- **Technology Stack**: Identified software, versions, and configurations
- **Potential Entry Points**: Highlighted potential security weaknesses

## Report Formats

The Reporting Engine supports multiple output formats:

### HTML

- Rich, interactive reports with navigation
- Embedded charts and graphs
- Collapsible sections for detailed information
- Responsive design for viewing on different devices

### PDF

- Professional, printable reports
- Consistent formatting and pagination
- Embedded images and diagrams
- Digital signatures for authenticity

### JSON

- Machine-readable format for integration with other tools
- Structured data for automated processing
- Complete access to all report data
- Suitable for API responses

### Plain Text

- Simple, accessible format
- Compatible with any system
- Easy to include in emails or messages
- Reduced file size

## Usage Examples

### Programmatic Usage

```python
from sentinelprobe.core.db import get_session
from sentinelprobe.reporting.service import ReportingService
from sentinelprobe.reporting.models import ReportRequest, ReportType, ReportFormat

async def generate_security_report(job_id: int):
    """Generate a comprehensive security report for a job."""
    async with get_session() as session:
        # Initialize the reporting service
        reporting_service = ReportingService(session=session)

        # Create a report request
        report_request = ReportRequest(
            job_id=job_id,
            report_type=ReportType.FULL,
            report_format=ReportFormat.HTML,
            title="Comprehensive Security Assessment",
            description="Full security assessment report with detailed findings and recommendations",
            include_findings=True,
            include_recommendations=True,
            custom_sections=["executive_summary", "methodology", "attack_paths"]
        )

        # Create the report
        report_id = await reporting_service.create_report(report_request)

        # Generate the report content
        report_path = await reporting_service.generate_report(report_id)

        print(f"Report generated successfully: {report_path}")

        # Get the report file path
        file_path = await reporting_service.get_report_file_path(report_id)

        return file_path
```

### API Usage

```python
import aiohttp
import asyncio

async def generate_report_via_api():
    """Generate a security report via the SentinelProbe API."""
    async with aiohttp.ClientSession() as session:
        # Create a report
        create_response = await session.post(
            "http://localhost:8000/api/reporting/reports",
            json={
                "job_id": 123,
                "report_type": "full",
                "report_format": "pdf",
                "title": "Security Assessment Report",
                "description": "Comprehensive security assessment of target systems",
                "include_findings": True,
                "include_recommendations": True,
                "custom_sections": ["executive_summary", "attack_paths"]
            }
        )

        create_data = await create_response.json()
        report_id = create_data["id"]

        # Generate the report
        generate_response = await session.post(
            f"http://localhost:8000/api/reporting/reports/{report_id}/generate"
        )

        generate_data = await generate_response.json()

        # Check generation status
        while True:
            status_response = await session.get(
                f"http://localhost:8000/api/reporting/reports/{report_id}"
            )
            status_data = await status_response.json()

            if status_data["status"] in ["completed", "failed"]:
                break

            await asyncio.sleep(2)

        if status_data["status"] == "completed":
            # Download the report
            download_response = await session.get(
                f"http://localhost:8000/api/reporting/reports/{report_id}/download"
            )

            # Save the report to a file
            with open(f"report_{report_id}.pdf", "wb") as f:
                f.write(await download_response.read())

            print(f"Report downloaded: report_{report_id}.pdf")
        else:
            print(f"Report generation failed: {status_data.get('error', 'Unknown error')}")

# Run the async function
loop = asyncio.get_event_loop()
loop.run_until_complete(generate_report_via_api())
```

### Command Line Usage

```bash
# Generate a full HTML report
python -m sentinelprobe reporting create \
    --job-id 123 \
    --type full \
    --format html \
    --title "Security Assessment Report" \
    --output-dir ./reports

# Generate a vulnerability-focused PDF report
python -m sentinelprobe reporting create \
    --job-id 123 \
    --type vulnerability \
    --format pdf \
    --title "Vulnerability Assessment" \
    --include-recommendations \
    --output-dir ./reports

# Generate a summary report for executives
python -m sentinelprobe reporting create \
    --job-id 123 \
    --type summary \
    --format pdf \
    --title "Executive Summary" \
    --template executive \
    --output-dir ./reports
```

## Report Templates

The Reporting Engine includes several built-in templates:

### Standard Template

The default template for comprehensive reports, featuring:

- Clean, professional design
- Detailed sections for all findings
- Charts and graphs for data visualization
- Color-coded severity indicators

### Executive Template

A concise template designed for management, featuring:

- Minimalist design focused on key information
- Risk dashboards and summary metrics
- Limited technical details
- Business impact assessments

### Technical Template

A detailed template for security teams, featuring:

- In-depth technical information
- Command outputs and evidence
- Detailed remediation steps
- References to security resources

## Customizing Reports

Reports can be customized in several ways:

### Custom Templates

Create custom templates by:

1. Creating a new HTML/CSS template file
2. Registering the template with the Reporting Engine
3. Specifying the template when generating reports

### Custom Sections

Add or remove sections from reports:

- Specify `custom_sections` in the report request
- Define section content in the template
- Order sections as needed

### Branding

Customize reports with organization branding:

- Add company logos
- Use corporate color schemes
- Include legal disclaimers
- Add contact information

## Integration with AI Decision Engine

The Reporting Engine integrates with the AI Decision Engine in several ways:

1. **Finding Prioritization**: The AI helps prioritize findings based on multiple factors
2. **Remediation Recommendations**: AI-generated recommendations for addressing vulnerabilities
3. **Risk Assessment**: AI-driven risk scoring and impact analysis
4. **Natural Language Summaries**: AI-generated natural language descriptions of technical findings

## Performance Considerations

To optimize the performance of the Reporting Engine:

- **Asynchronous Generation**: Reports are generated asynchronously to avoid blocking
- **Caching**: Report data is cached to improve performance for repeated access
- **Pagination**: Large reports are paginated to improve rendering performance
- **Resource Management**: Large reports are generated with controlled resource usage

## Security Considerations

When using the Reporting Engine:

- **Access Control**: Reports contain sensitive information and should be protected
- **Data Handling**: Report data should be stored securely
- **Transmission Security**: Reports should be transmitted over secure channels
- **Retention Policies**: Implement appropriate retention policies for reports

## Troubleshooting

### Common Issues

1. **Report Generation Failures**:
   - Check that all required data is available
   - Verify that the job has completed successfully
   - Check for errors in the report generation logs
   - Ensure sufficient disk space for report storage

2. **Missing Data in Reports**:
   - Verify that all modules have completed their tasks
   - Check that data collection was successful
   - Ensure the correct report type was selected
   - Verify template compatibility with the data

3. **Formatting Issues**:
   - Check template compatibility with the report format
   - Verify CSS and styling resources are available
   - Ensure the rendering engine has all required dependencies
   - Test with different browsers for HTML reports

## API Reference

For a complete API reference, see the [API Documentation](../advanced/api-reference.md#reporting-engine).
