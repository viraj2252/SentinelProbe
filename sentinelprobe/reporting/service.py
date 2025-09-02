"""Service layer for the Reporting Engine."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, cast

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.ai_decision.repository import KnowledgeRepository
from sentinelprobe.orchestration.repository import JobRepository
from sentinelprobe.reconnaissance.repository import (
    PortRepository,
    ServiceRepository,
    TargetRepository,
)
from sentinelprobe.reporting.models import (
    ReportData,
    ReportFormat,
    ReportRequest,
    ReportStatus,
    SeverityLevel,
    VulnerabilityFindings,
)
from sentinelprobe.reporting.repository import ReportRepository
from sentinelprobe.vulnerability_scanner.models import VulnerabilitySeverity
from sentinelprobe.vulnerability_scanner.repository import VulnerabilityRepository


class ReportingService:
    """Service for report generation and management."""

    def __init__(
        self,
        session: AsyncSession,
        report_repository: Optional[ReportRepository] = None,
        job_repository: Optional[JobRepository] = None,
        vulnerability_repository: Optional[VulnerabilityRepository] = None,
        knowledge_repository: Optional[KnowledgeRepository] = None,
    ):
        """Initialize reporting service."""
        self.session: AsyncSession = session
        self.report_repository = report_repository or ReportRepository(session)
        self.job_repository = job_repository or JobRepository(session)
        self.vulnerability_repository = vulnerability_repository or (
            VulnerabilityRepository(session)
        )
        self.knowledge_repository = knowledge_repository or (
            KnowledgeRepository(session)
        )
        # Recon repositories for assembling reconnaissance data
        self.target_repository = TargetRepository(session)
        self.port_repository = PortRepository(session)
        self.service_repository = ServiceRepository(session)

    # _get_session helper no longer needed as session is injected

    async def create_report(self, request: ReportRequest) -> int:
        """
        Create a new report.

        Args:
            request: Report generation request

        Returns:
            ID of the created report
        """
        # Create the report record
        report = await self.report_repository.create_report(
            job_id=request.job_id,
            report_type=request.report_type,
            report_format=request.report_format,
            title=request.title,
            description=request.description,
            metadata=request.metadata,
        )

        return cast(int, report.id)

    async def generate_report(self, report_id: int) -> str:
        """
        Generate a report based on its ID.

        Args:
            report_id: ID of the report to generate

        Returns:
            Path to the generated report file
        """
        # Get the report record
        report = await self.report_repository.get_report(report_id)
        if not report:
            raise ValueError(f"Report with ID {report_id} not found")

        # Update status to in progress
        await self.report_repository.update_report_status(
            report_id, ReportStatus.IN_PROGRESS
        )

        try:
            # Collect data for the report
            report_data = await self._collect_report_data(report)

            # Store the report data in MongoDB
            await self.report_repository.store_report_data(report_data)

            # Generate the report content based on format
            content = await self._generate_report_content(
                report_data, report.report_format
            )

            # Save the report to a file
            file_path = await self.report_repository.save_report_file(
                report_id, content, report.report_format
            )

            # Update status to completed
            await self.report_repository.update_report_status(
                report_id, ReportStatus.COMPLETED
            )

            return file_path
        except Exception as e:
            # Update status to failed
            await self.report_repository.update_report_status(
                report_id, ReportStatus.FAILED
            )
            raise e

    async def _collect_report_data(self, report: Any) -> ReportData:
        """
        Collect data for a report.

        Args:
            report: Report record

        Returns:
            Collected report data
        """
        # Get job information
        job = await self.job_repository.get_job(report.job_id)
        if not job:
            raise ValueError(f"Job with ID {report.job_id} not found")

        # Collect reconnaissance-related context
        targets = await self.target_repository.get_targets_by_job(report.job_id)

        recon_data: Dict[str, Any] = {"targets": []}
        for t in targets:
            # Ports and services per target
            ports = await self.port_repository.get_ports_by_target(t.id)
            services: List[Dict[str, Any]] = []
            for p in ports:
                svc = await self.service_repository.get_service_by_port(p.id)
                if svc:
                    services.append(
                        {
                            "port": p.port_number,
                            "protocol": p.protocol,
                            "service_type": svc.service_type.value,
                            "name": svc.name,
                            "version": svc.version or "",
                        }
                    )
            recon_data["targets"].append(
                {
                    "id": t.id,
                    "hostname": t.hostname,
                    "ip_address": t.ip_address,
                    "status": t.status.value,
                    "open_ports": [
                        p.port_number
                        for p in ports
                        if str(p.status.value).lower() != "closed"
                    ],
                    "services": services,
                }
            )

        # Collect vulnerabilities per target for this job
        findings: List[VulnerabilityFindings] = []
        severity_map = {
            VulnerabilitySeverity.CRITICAL: SeverityLevel.CRITICAL,
            VulnerabilitySeverity.HIGH: SeverityLevel.HIGH,
            VulnerabilitySeverity.MEDIUM: SeverityLevel.MEDIUM,
            VulnerabilitySeverity.LOW: SeverityLevel.LOW,
            VulnerabilitySeverity.INFO: SeverityLevel.INFO,
        }

        for t in targets:
            vulns = await self.vulnerability_repository.get_vulnerabilities_by_target(
                t.id
            )
            for v in vulns:
                # Resolve affected target details
                port_info: Optional[Dict[str, Any]] = None
                if v.port_number is not None and v.protocol:
                    port = await self.port_repository.get_port_by_number(
                        t.id, int(v.port_number), v.protocol
                    )
                    if port:
                        svc = await self.service_repository.get_service_by_port(port.id)
                        port_info = {
                            "ip": t.ip_address,
                            "port": port.port_number,
                            "service": svc.name if svc else None,
                        }
                affected_targets = (
                    [port_info]
                    if port_info
                    else [{"ip": t.ip_address, "port": v.port_number, "service": None}]
                )

                references = None
                if v.details and isinstance(v.details, dict):
                    refs = v.details.get("references")
                    if isinstance(refs, list):
                        references = refs

                remediation_steps = [v.remediation] if v.remediation else None

                finding = VulnerabilityFindings(
                    id=int(v.id),
                    title=v.name,
                    description=v.description,
                    severity=severity_map.get(v.severity, SeverityLevel.LOW),
                    cvss_score=(
                        float(v.cvss_score) if v.cvss_score is not None else None
                    ),
                    cve_id=v.cve_id,
                    affected_targets=affected_targets,
                    remediation_steps=remediation_steps,
                    references=references,
                    metadata=v.details or {},
                )
                findings.append(finding)

        # Create report data
        summary = f"Security assessment for job {job.name} (ID: {job.id})"
        report_data = ReportData(
            report_id=report.id,
            job_id=report.job_id,
            title=report.title,
            description=report.description,
            summary=summary,
            findings=findings,
            reconnaissance_data=recon_data,
            remediation_summary=self._generate_remediation_summary(findings),
            metadata=report.metadata,
            created_at=datetime.utcnow(),
        )

        return report_data

    def _generate_remediation_summary(
        self, findings: List[VulnerabilityFindings]
    ) -> Dict[str, Any]:
        """
        Generate a summary of remediation steps.

        Args:
            findings: List of vulnerability findings

        Returns:
            Remediation summary
        """
        # Group findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity_counts[finding.severity.value] += 1

        # Extract unique remediation steps
        remediation_steps = set()
        for finding in findings:
            if finding.remediation_steps:
                for step in finding.remediation_steps:
                    remediation_steps.add(step)

        return {
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "remediation_steps": list(remediation_steps),
            "priority_findings": [
                f.title for f in findings if f.severity.value in ["critical", "high"]
            ],
        }

    async def _generate_report_content(
        self, report_data: ReportData, report_format: ReportFormat
    ) -> str:
        """
        Generate report content based on format.

        Args:
            report_data: Report data
            report_format: Format of the report

        Returns:
            Generated report content
        """
        if report_format == ReportFormat.JSON:
            return json.dumps(report_data.dict(), indent=2)
        elif report_format == ReportFormat.TEXT:
            return self._generate_text_report(report_data)
        elif report_format == ReportFormat.HTML:
            return self._generate_html_report(report_data)
        elif report_format == ReportFormat.PDF:
            # For PDF, we'll generate HTML first and then convert it
            # This is a placeholder for now
            return self._generate_html_report(report_data)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")

    def _generate_text_report(self, report_data: ReportData) -> str:
        """
        Generate a text report.

        Args:
            report_data: Report data

        Returns:
            Text report content
        """
        lines = []
        lines.append("=" * 80)
        lines.append(f"SECURITY ASSESSMENT REPORT: {report_data.title}")
        lines.append("=" * 80)
        lines.append("")

        if report_data.description:
            lines.append(report_data.description)
            lines.append("")

        if report_data.summary:
            lines.append("SUMMARY")
            lines.append("-" * 80)
            lines.append(report_data.summary)
            lines.append("")

        if report_data.findings:
            lines.append("VULNERABILITY FINDINGS")
            lines.append("-" * 80)

            for finding in report_data.findings:
                lines.append(f"[{finding.severity.value.upper()}] {finding.title}")
                lines.append(f"ID: {finding.id}")
                if finding.cve_id:
                    lines.append(f"CVE: {finding.cve_id}")
                if finding.cvss_score:
                    lines.append(f"CVSS Score: {finding.cvss_score}")
                lines.append("")
                lines.append(finding.description)
                lines.append("")

                lines.append("Affected Targets:")
                for target in finding.affected_targets:
                    target_str = f"- {target.get('ip', 'Unknown IP')}"
                    if target.get("port"):
                        target_str += f":{target.get('port')}"
                    if target.get("service"):
                        target_str += f" ({target.get('service')})"
                    lines.append(target_str)
                lines.append("")

                if finding.remediation_steps:
                    lines.append("Remediation Steps:")
                    for step in finding.remediation_steps:
                        lines.append(f"- {step}")
                    lines.append("")

                if finding.references:
                    lines.append("References:")
                    for ref in finding.references:
                        lines.append(f"- {ref}")
                    lines.append("")

                lines.append("-" * 40)
                lines.append("")

        if report_data.remediation_summary:
            lines.append("REMEDIATION SUMMARY")
            lines.append("-" * 80)

            severity_counts = report_data.remediation_summary.get("severity_counts", {})
            lines.append("Findings by Severity:")
            for severity, count in severity_counts.items():
                lines.append(f"- {severity.upper()}: {count}")
            lines.append("")

            priority_findings = report_data.remediation_summary.get(
                "priority_findings", []
            )
            if priority_findings:
                lines.append("Priority Findings:")
                for finding in priority_findings:
                    lines.append(f"- {finding}")
                lines.append("")

        lines.append("=" * 80)
        lines.append(f"Report generated on: {report_data.created_at}")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_html_report(self, report_data: ReportData) -> str:
        """
        Generate an HTML report.

        Args:
            report_data: Report data

        Returns:
            HTML report content
        """
        # This is a simple HTML template for now
        # In a real implementation, we would use a proper templating engine
        style = """
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2, h3 { color: #333; }
            .header { background-color: #f5f5f5; padding: 10px;
                      border-bottom: 1px solid #ddd; }
            .section { margin-bottom: 20px; }
            .finding { border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; }
            .critical { border-left: 5px solid #d9534f; }
            .high { border-left: 5px solid #f0ad4e; }
            .medium { border-left: 5px solid #5bc0de; }
            .low { border-left: 5px solid #5cb85c; }
            .info { border-left: 5px solid #5bc0de; }
            .footer { margin-top: 30px; font-size: 0.8em; color: #777; }
        """

        html = [
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{report_data.title}</title>
                <style>{style}</style>
            </head>
            <body>
                <div class="header">
                    <h1>{report_data.title}</h1>
                    <p>{report_data.description or ''}</p>
                </div>

                <div class="section">
                    <h2>Summary</h2>
                    <p>{report_data.summary or 'No summary available.'}</p>
                </div>
            """
        ]

        if report_data.findings:
            html.append(
                """
                <div class="section">
                    <h2>Vulnerability Findings</h2>
            """
            )

            for finding in report_data.findings:
                html.append(
                    f"""
                    <div class="finding {finding.severity.value}">
                        <h3>[{finding.severity.value.upper()}] {finding.title}</h3>
                        <p><strong>ID:</strong> {finding.id}</p>
                """
                )

                if finding.cve_id:
                    html.append(f"<p><strong>CVE:</strong> {finding.cve_id}</p>")

                if finding.cvss_score:
                    html.append(
                        f"<p><strong>CVSS Score:</strong> {finding.cvss_score}</p>"
                    )

                html.append(f"<p>{finding.description}</p>")

                html.append("<p><strong>Affected Targets:</strong></p><ul>")
                for target in finding.affected_targets:
                    target_str = f"{target.get('ip', 'Unknown IP')}"
                    if target.get("port"):
                        target_str += f":{target.get('port')}"
                    if target.get("service"):
                        target_str += f" ({target.get('service')})"
                    html.append(f"<li>{target_str}</li>")
                html.append("</ul>")

                if finding.remediation_steps:
                    html.append("<p><strong>Remediation Steps:</strong></p><ul>")
                    for step in finding.remediation_steps:
                        html.append(f"<li>{step}</li>")
                    html.append("</ul>")

                if finding.references:
                    html.append("<p><strong>References:</strong></p><ul>")
                    for ref in finding.references:
                        html.append(f"<li>{ref}</li>")
                    html.append("</ul>")

                html.append("</div>")

            html.append("</div>")

        if report_data.remediation_summary:
            html.append(
                """
                <div class="section">
                    <h2>Remediation Summary</h2>
            """
            )

            severity_counts = report_data.remediation_summary.get("severity_counts", {})
            html.append("<p><strong>Findings by Severity:</strong></p><ul>")
            for severity, count in severity_counts.items():
                html.append(f"<li>{severity.upper()}: {count}</li>")
            html.append("</ul>")

            priority_findings = report_data.remediation_summary.get(
                "priority_findings", []
            )
            if priority_findings:
                html.append("<p><strong>Priority Findings:</strong></p><ul>")
                for finding in priority_findings:
                    html.append(f"<li>{finding}</li>")
                html.append("</ul>")

            html.append("</div>")

        html.append(
            f"""
                <div class="footer">
                    <p>Report generated on: {report_data.created_at}</p>
                </div>
            </body>
            </html>
        """
        )

        return "".join(html)

    async def get_report_file_path(self, report_id: int) -> Optional[str]:
        """
        Get the file path for a report.

        Args:
            report_id: ID of the report

        Returns:
            Path to the report file if available, otherwise None
        """
        report = await self.report_repository.get_report(report_id)
        if not report or not report.content_path:
            return None
        return cast(Optional[str], report.content_path)

    async def delete_report(self, report_id: int) -> bool:
        """
        Delete a report.

        Args:
            report_id: ID of the report

        Returns:
            True if successfully deleted, False otherwise
        """
        return await self.report_repository.delete_report(report_id)
