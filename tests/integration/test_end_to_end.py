"""Integration tests for the complete end-to-end SentinelProbe workflow."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelprobe.ai_decision.models import (
    DecisionRule,
    DecisionRuleSeverity,
    DecisionRuleType,
    StrategyPhase,
    TestStrategy,
)
from sentinelprobe.ai_decision.repository import (
    DecisionRuleRepository,
    TestStrategyRepository,
)
from sentinelprobe.ai_decision.service import DecisionEngineService
from sentinelprobe.orchestration.models import Job, JobStatus, JobType, Task, TaskStatus
from sentinelprobe.orchestration.repository import JobRepository, TaskRepository
from sentinelprobe.orchestration.service import OrchestrationService
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
from sentinelprobe.reporting.models import (
    Report,
    ReportFormat,
    ReportStatus,
    ReportType,
)
from sentinelprobe.reporting.repository import ReportRepository
from sentinelprobe.reporting.service import ReportingService
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


class Decision:
    """Mock Decision class for testing."""

    def __init__(
        self,
        id,
        rule_id,
        target_id,
        vulnerability_id,
        scan_id,
        action,
        action_params,
        result,
    ):
        self.id = id
        self.rule_id = rule_id
        self.target_id = target_id
        self.vulnerability_id = vulnerability_id
        self.scan_id = scan_id
        self.action = action
        self.action_params = action_params
        self.result = result


class DecisionRepository:
    """Mock repository for Decision objects used in testing."""

    def __init__(self, session):
        self.session = session
        self.decisions = []

    async def create_decision(
        self,
        rule_id,
        target_id,
        vulnerability_id,
        scan_id,
        action,
        action_params,
        result,
    ):
        decision = Decision(
            id=len(self.decisions) + 1,
            rule_id=rule_id,
            target_id=target_id,
            vulnerability_id=vulnerability_id,
            scan_id=scan_id,
            action=action,
            action_params=action_params,
            result=result,
        )
        self.decisions.append(decision)
        return decision

    async def get_decisions_by_vulnerability(self, vulnerability_id):
        return [d for d in self.decisions if d.vulnerability_id == vulnerability_id]

    async def get_decisions_by_target(self, target_id):
        return [d for d in self.decisions if d.target_id == target_id]


@pytest.mark.asyncio
class TestEndToEndWorkflow:
    """Test the complete end-to-end workflow of SentinelProbe."""

    async def test_complete_workflow(self, mock_session):
        """Test the full workflow from job creation to report generation."""
        # Set up repositories
        job_repo = JobRepository(mock_session)
        task_repo = TaskRepository(mock_session)
        target_repo = TargetRepository(mock_session)
        port_repo = PortRepository(mock_session)
        service_repo = ServiceRepository(mock_session)
        vuln_scan_repo = VulnerabilityScanRepository(mock_session)
        vuln_repo = VulnerabilityRepository(mock_session)
        strategy_repo = TestStrategyRepository(mock_session)
        rule_repo = DecisionRuleRepository(mock_session)
        report_repo = ReportRepository(mock_session)

        # Create a mock job
        job = Job(
            id=1,
            name="Test End-to-End Scan",
            description="Comprehensive test of full SentinelProbe workflow",
            job_type=JobType.SCAN,
            status=JobStatus.PENDING,
            target="test-target.example.com",
            config={
                "target_hostname": "test-target.example.com",
                "target_ip": "192.168.1.100",
                "scan_depth": "standard",
            },
        )

        job_repo.create_job = AsyncMock(return_value=job)
        job_repo.get_job = AsyncMock(return_value=job)
        job_repo.update_job_status = AsyncMock(return_value=job)

        # Create tasks for the job
        recon_task = Task(
            id=1,
            job_id=job.id,
            name="Reconnaissance",
            description="Perform reconnaissance on the target",
            status=TaskStatus.PENDING,
        )

        vuln_scan_task = Task(
            id=2,
            job_id=job.id,
            name="Vulnerability Scanning",
            description="Scan for vulnerabilities on the target",
            status=TaskStatus.PENDING,
        )

        ai_decision_task = Task(
            id=3,
            job_id=job.id,
            name="AI Decision Making",
            description="Analyze vulnerabilities and make decisions",
            status=TaskStatus.PENDING,
        )

        reporting_task = Task(
            id=4,
            job_id=job.id,
            name="Reporting",
            description="Generate final report",
            status=TaskStatus.PENDING,
        )

        task_repo.create_task = AsyncMock()
        task_repo.create_task.side_effect = [
            recon_task,
            vuln_scan_task,
            ai_decision_task,
            reporting_task,
        ]
        task_repo.get_task = AsyncMock()
        task_repo.update_task_status = AsyncMock()

        # Configure conditional returns for get_task
        async def get_task_side_effect(task_id):
            if task_id == recon_task.id:
                return recon_task
            elif task_id == vuln_scan_task.id:
                return vuln_scan_task
            elif task_id == ai_decision_task.id:
                return ai_decision_task
            elif task_id == reporting_task.id:
                return reporting_task
            return None

        task_repo.get_task.side_effect = get_task_side_effect

        # Configure conditional returns for update_task_status
        async def update_task_status_side_effect(task_id, status):
            if task_id == recon_task.id:
                recon_task.status = status
                return recon_task
            elif task_id == vuln_scan_task.id:
                vuln_scan_task.status = status
                return vuln_scan_task
            elif task_id == ai_decision_task.id:
                ai_decision_task.status = status
                return ai_decision_task
            elif task_id == reporting_task.id:
                reporting_task.status = status
                return reporting_task
            return None

        task_repo.update_task_status.side_effect = update_task_status_side_effect
        task_repo.get_tasks_by_job = AsyncMock(
            return_value=[recon_task, vuln_scan_task, ai_decision_task, reporting_task]
        )
        task_repo.get_pending_tasks = AsyncMock(return_value=[recon_task])

        # Create a mock target
        target = Target(
            id=1,
            job_id=job.id,
            hostname="test-target.example.com",
            ip_address="192.168.1.100",
            status=TargetStatus.PENDING,
            target_metadata={"environment": "production", "criticality": "high"},
        )

        target_repo.create_target = AsyncMock(return_value=target)
        target_repo.get_target = AsyncMock(return_value=target)
        target_repo.update_target_status = AsyncMock(return_value=target)

        # Set up port scanner with mocked scan results
        scanner_service = PortScannerService(mock_session, port_repo, service_repo)
        scanner_service._scan_ports = AsyncMock(
            return_value=[
                {"port": 22, "status": "open", "protocol": "tcp"},
                {"port": 80, "status": "open", "protocol": "tcp"},
                {"port": 443, "status": "open", "protocol": "tcp"},
                {"port": 27017, "status": "open", "protocol": "tcp"},  # MongoDB port
            ]
        )

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

        # Mock service detection
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

        # Create vulnerability scanner with mock scan results
        vuln_scanner_service = VulnerabilityScannerService(mock_session)

        # Create a mock scan
        vuln_scan = VulnerabilityScan(
            id=1,
            job_id=job.id,
            target_id=target.id,
            strategy_id=None,
            name="MongoDB Scan",
            description="MongoDB vulnerability scan",
            scan_type=ScanType.STANDARD,
            scanner_module="mongodb_scanner",
            status=ScanStatus.PENDING,
            parameters={},
            scan_metadata={},
        )

        vuln_scan_repo.create_scan = AsyncMock(return_value=vuln_scan)
        vuln_scan_repo.get_scan = AsyncMock(return_value=vuln_scan)
        vuln_scan_repo.update_scan_status = AsyncMock(return_value=vuln_scan)
        vuln_scan_repo.get_scans_by_job = AsyncMock(return_value=[vuln_scan])

        # Create mock vulnerabilities
        auth_vulnerability = Vulnerability(
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

        http_vulnerability = Vulnerability(
            id=2,
            scan_id=vuln_scan.id,
            target_id=target.id,
            name="MongoDB HTTP Interface Enabled",
            description="MongoDB HTTP interface is enabled which increases attack surface.",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="MongoDB 4.2.1",
            port_number=27017,
            protocol="tcp",
            details={
                "http_interface": "enabled",
                "recommendation": "Disable HTTP interface unless necessary.",
            },
            remediation="Disable the HTTP interface by setting net.http.enabled to false.",
        )

        vuln_repo.create_vulnerability = AsyncMock()
        vuln_repo.create_vulnerability.side_effect = [
            auth_vulnerability,
            http_vulnerability,
        ]
        vuln_repo.get_vulnerabilities_by_scan = AsyncMock(
            return_value=[auth_vulnerability, http_vulnerability]
        )
        vuln_repo.get_vulnerabilities_by_target = AsyncMock(
            return_value=[auth_vulnerability, http_vulnerability]
        )

        # Mock the MongoDB scanner plugin
        mongodb_scanner_mock = AsyncMock()
        mongodb_scanner_mock.scan = AsyncMock(
            return_value=[
                {
                    "scan_id": vuln_scan.id,
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
                },
                {
                    "scan_id": vuln_scan.id,
                    "target_id": target.id,
                    "name": "MongoDB HTTP Interface Enabled",
                    "description": "MongoDB HTTP interface is enabled which increases attack surface.",
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "status": VulnerabilityStatus.UNCONFIRMED,
                    "affected_component": "MongoDB 4.2.1",
                    "port_number": 27017,
                    "protocol": "tcp",
                    "details": {
                        "http_interface": "enabled",
                        "recommendation": "Disable HTTP interface unless necessary.",
                    },
                    "remediation": "Disable the HTTP interface by setting net.http.enabled to false.",
                },
            ]
        )

        # Set up the scanner plugin mock return
        async def get_scanner_plugin_side_effect(scanner_name):
            if scanner_name == "mongodb_scanner":
                return mongodb_scanner_mock
            return None

        vuln_scanner_service.get_scanner_plugin = AsyncMock(
            side_effect=get_scanner_plugin_side_effect
        )
        vuln_scanner_service.create_scan = AsyncMock(return_value=vuln_scan)
        vuln_scanner_service.start_scan = AsyncMock(return_value=vuln_scan)
        vuln_scanner_service.create_vulnerability = AsyncMock()
        vuln_scanner_service.create_vulnerability.side_effect = [
            auth_vulnerability,
            http_vulnerability,
        ]

        # Set up AI decision engine
        ai_service = DecisionEngineService(mock_session)

        # Create a mock strategy
        strategy = TestStrategy(
            id=1,
            job_id=job.id,
            name="Production Database Assessment",
            description="Assesses vulnerabilities in production databases",
            phase=StrategyPhase.VULNERABILITY_SCAN,
            is_active=True,
            parameters={},
            strategy_metadata={
                "target_criteria": {
                    "environments": ["production"],
                    "criticality": ["high", "medium"],
                },
                "vulnerability_threshold": {"high": 1, "medium": 2, "low": 5},
            },
        )

        strategy_repo.get_active_strategies = AsyncMock(return_value=[strategy])
        strategy_repo.get_strategy = AsyncMock(return_value=strategy)
        strategy_repo.create_strategy = AsyncMock(return_value=strategy)

        # Create mock rules
        auth_rule = DecisionRule(
            id=1,
            name="High Severity Auth Issues",
            description="Rule for high severity authentication issues",
            rule_type=DecisionRuleType.VULNERABILITY_SCAN,
            severity=DecisionRuleSeverity.HIGH,
            conditions={
                "severity": "HIGH",
                "keywords": ["authentication", "credentials", "password", "auth"],
            },
            actions={
                "action": "escalate",
                "params": {"priority": "immediate", "notify": ["security_team"]},
            },
            is_active=True,
            priority=10,
            rule_metadata={},
        )

        config_rule = DecisionRule(
            id=2,
            name="Medium Severity Config Issues",
            description="Rule for medium severity configuration issues",
            rule_type=DecisionRuleType.VULNERABILITY_SCAN,
            severity=DecisionRuleSeverity.MEDIUM,
            conditions={
                "severity": "MEDIUM",
                "keywords": ["configuration", "config", "interface", "exposure"],
            },
            actions={
                "action": "log",
                "params": {"priority": "high", "notify": ["system_admin"]},
            },
            is_active=True,
            priority=20,
            rule_metadata={},
        )

        rule_repo.get_rules_by_strategy = AsyncMock(
            return_value=[auth_rule, config_rule]
        )
        rule_repo.create_rule = AsyncMock(side_effect=[auth_rule, config_rule])

        # Mock the AI service methods
        ai_service.create_vulnerability_based_rules = AsyncMock(
            return_value=[auth_rule, config_rule]
        )
        ai_service._target_matches_strategy = MagicMock(return_value=True)

        # Mock analyze_vulnerability_prioritization
        async def mock_analyze_vulnerability_prioritization(target_id, job_id):
            return strategy

        ai_service.analyze_vulnerability_prioritization = AsyncMock(
            side_effect=mock_analyze_vulnerability_prioritization
        )

        # Set up reporting service
        reporting_service = ReportingService(mock_session)

        # Create a mock report
        report = Report(
            id=1,
            job_id=job.id,
            title="Security Assessment Report",
            description="Comprehensive security assessment for test-target.example.com",
            report_type=ReportType.FULL,
            report_format=ReportFormat.JSON,
            status=ReportStatus.PENDING,
            content_path=None,
        )

        report_repo.create_report = AsyncMock(return_value=report)
        report_repo.get_report = AsyncMock(return_value=report)
        report_repo.update_report = AsyncMock(return_value=report)

        # Mock the generate_report method
        async def mock_generate_report(report_id):
            report_content = {
                "summary": {
                    "target": "test-target.example.com",
                    "scan_date": "2023-04-15T10:00:00Z",
                    "total_vulnerabilities": 2,
                    "high_severity": 1,
                    "medium_severity": 1,
                    "low_severity": 0,
                },
                "vulnerabilities": [
                    {
                        "id": auth_vulnerability.id,
                        "name": auth_vulnerability.name,
                        "description": auth_vulnerability.description,
                        "severity": "HIGH",
                        "affected_component": auth_vulnerability.affected_component,
                        "remediation": auth_vulnerability.remediation,
                        "decisions": [
                            {
                                "action": auth_rule.actions.get("action", ""),
                                "result": auth_rule.actions.get("result", {}),
                            }
                        ],
                    },
                    {
                        "id": http_vulnerability.id,
                        "name": http_vulnerability.name,
                        "description": http_vulnerability.description,
                        "severity": "MEDIUM",
                        "affected_component": http_vulnerability.affected_component,
                        "remediation": http_vulnerability.remediation,
                        "decisions": [
                            {
                                "action": config_rule.actions.get("action", ""),
                                "result": config_rule.actions.get("result", {}),
                            }
                        ],
                    },
                ],
                "recommendations": [
                    "Enable MongoDB authentication immediately as this is a critical security issue.",
                    "Disable the MongoDB HTTP interface unless it is absolutely necessary for operations.",
                ],
            }

            # Update the report with content
            report.content = report_content
            report.status = ReportStatus.COMPLETED
            return report

        reporting_service.generate_report = AsyncMock(side_effect=mock_generate_report)

        # Set up orchestration service
        orchestration_service = OrchestrationService(mock_session)

        # Mock the necessary orchestration methods
        orchestration_service.create_job = AsyncMock(return_value=job)
        orchestration_service.get_job = AsyncMock(return_value=job)
        orchestration_service.update_job_status = AsyncMock(return_value=job)
        orchestration_service.create_task = AsyncMock()
        orchestration_service.create_task.side_effect = [
            recon_task,
            vuln_scan_task,
            ai_decision_task,
            reporting_task,
        ]
        orchestration_service.get_task = AsyncMock(side_effect=get_task_side_effect)
        orchestration_service.update_task_status = AsyncMock(
            side_effect=update_task_status_side_effect
        )
        orchestration_service.get_pending_tasks = AsyncMock(return_value=[recon_task])

        # PHASE 1: Start a new job
        new_job = await orchestration_service.create_job(
            name="Test End-to-End Scan",
            description="Comprehensive test of full SentinelProbe workflow",
            job_type=JobType.SCAN,
            target="test-target.example.com",
            config={
                "target_hostname": "test-target.example.com",
                "target_ip": "192.168.1.100",
                "scan_depth": "standard",
            },
        )

        # Create tasks for the job
        await orchestration_service.create_task(
            job_id=new_job.id,
            name="Reconnaissance",
            description="Perform reconnaissance on the target",
        )

        await orchestration_service.create_task(
            job_id=new_job.id,
            name="Vulnerability Scanning",
            description="Scan for vulnerabilities on the target",
        )

        await orchestration_service.create_task(
            job_id=new_job.id,
            name="AI Decision Making",
            description="Analyze vulnerabilities and make decisions",
        )

        await orchestration_service.create_task(
            job_id=new_job.id, name="Reporting", description="Generate final report"
        )

        # Start job
        await orchestration_service.update_job_status(job.id, JobStatus.RUNNING)

        # PHASE 2: Execute reconnaissance task
        # Update task status
        await orchestration_service.update_task_status(
            recon_task.id, TaskStatus.RUNNING
        )

        # Create a target from job parameters
        new_target = await target_repo.create_target(
            job_id=job.id,
            hostname=job.config.get("target_hostname"),
            ip_address=job.config.get("target_ip"),
            status=TargetStatus.PENDING,
            target_metadata={"environment": "production", "criticality": "high"},
        )

        # Perform port scanning
        await scanner_service.scan_target(new_target.id)

        # Perform service detection
        ports = await port_repo.get_ports_by_target(new_target.id)
        for port in ports:
            await service_detector.detect_service(port)

        # Complete reconnaissance task
        await orchestration_service.update_task_status(
            recon_task.id, TaskStatus.COMPLETED
        )

        # PHASE 3: Execute vulnerability scanning task
        # Update task status
        await orchestration_service.update_task_status(
            vuln_scan_task.id, TaskStatus.RUNNING
        )

        # Get services for target by type
        mongodb_services = await service_repo.get_services_by_target_and_type(
            new_target.id, ServiceType.MONGODB
        )

        if mongodb_services:
            # Create a vulnerability scan for MongoDB
            scan = await vuln_scanner_service.create_scan(
                job_id=job.id,
                target_id=new_target.id,
                name="MongoDB Security Scan",
                description="Scanning MongoDB for vulnerabilities",
                scan_type=ScanType.STANDARD,
                scanner_module="mongodb_scanner",
                parameters={},
            )

            # Start the scan
            await vuln_scanner_service.start_scan(scan.id)

        # Complete vulnerability scanning task
        await orchestration_service.update_task_status(
            vuln_scan_task.id, TaskStatus.COMPLETED
        )

        # PHASE 4: Execute AI decision task
        # Update task status
        await orchestration_service.update_task_status(
            ai_decision_task.id, TaskStatus.RUNNING
        )

        # Use the AI decision engine to analyze vulnerabilities
        strategy = await ai_service.analyze_vulnerability_prioritization(
            new_target.id, job.id
        )

        # Verify that the strategy was created
        assert strategy is not None
        assert strategy.job_id == job.id

        # Complete AI decision task
        await orchestration_service.update_task_status(
            ai_decision_task.id, TaskStatus.COMPLETED
        )

        # PHASE 5: Execute reporting task
        # Update task status
        await orchestration_service.update_task_status(
            reporting_task.id, TaskStatus.RUNNING
        )

        # Create a report
        new_report = await report_repo.create_report(
            job_id=job.id,
            name="Security Assessment Report",
            description=f"Comprehensive security assessment for {new_target.hostname}",
            status=ReportStatus.PENDING,
            format=ReportFormat.JSON,
            content=None,
        )

        # Generate the report
        completed_report = await reporting_service.generate_report(new_report.id)

        # Complete reporting task
        await orchestration_service.update_task_status(
            reporting_task.id, TaskStatus.COMPLETED
        )

        # Complete job
        await orchestration_service.update_job_status(job.id, JobStatus.COMPLETED)

        # ASSERTIONS

        # Verify job creation and completion
        assert job.id == 1
        assert job.status == JobStatus.COMPLETED

        # Verify task creation and completion
        assert recon_task.status == TaskStatus.COMPLETED
        assert vuln_scan_task.status == TaskStatus.COMPLETED
        assert ai_decision_task.status == TaskStatus.COMPLETED
        assert reporting_task.status == TaskStatus.COMPLETED

        # Verify target creation
        assert target.hostname == "test-target.example.com"
        assert target.ip_address == "192.168.1.100"

        # Verify port scanning
        assert port_repo.create_port.call_count == 4

        # Verify service detection
        assert service_repo.create_service.call_count == 4

        # Verify vulnerability scanning
        assert vuln_scan_repo.create_scan.call_count == 1
        assert vuln_repo.create_vulnerability.call_count == 2

        # Verify AI decision making
        assert rule_repo.create_rule.call_count == 2

        # Verify report generation
        assert report_repo.create_report.call_count == 1
        assert completed_report.status == ReportStatus.COMPLETED
        assert completed_report.content is not None
        assert completed_report.content["summary"]["total_vulnerabilities"] == 2
        assert completed_report.content["summary"]["high_severity"] == 1
        assert len(completed_report.content["vulnerabilities"]) == 2
        assert len(completed_report.content["recommendations"]) == 2
