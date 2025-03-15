"""Service layer for the AI Decision Engine."""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.ai_decision.models import (
    AdaptiveRule,
    AdaptiveRuleCreate,
    ConfidenceLevel,
    ContextType,
    ContextualScore,
    ContextualScoreCreate,
    DecisionRule,
    DecisionRuleCreate,
    DecisionRuleSeverity,
    DecisionRuleType,
    StrategyPhase,
    TestStrategy,
    TestStrategyCreate,
    VulnerabilityCorrelation,
    VulnerabilityCorrelationCreate,
)
from sentinelprobe.ai_decision.repository import (
    AdaptiveRuleRepository,
    ContextualScoreRepository,
    DecisionRuleRepository,
    KnowledgeRepository,
    TestStrategyRepository,
    VulnerabilityCorrelationRepository,
)
from sentinelprobe.reconnaissance.models import ServiceType, Target
from sentinelprobe.reconnaissance.repository import TargetRepository
from sentinelprobe.vulnerability_scanner.models import (
    Vulnerability,
    VulnerabilitySeverity,
)
from sentinelprobe.vulnerability_scanner.repository import VulnerabilityRepository
from sentinelprobe.vulnerability_scanner.service import VulnerabilityScannerService

logger = logging.getLogger(__name__)


class DecisionEngineService:
    """Service for the AI Decision Engine."""

    def __init__(self, session: AsyncSession):
        """Initialize with session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session
        self.knowledge_repo = KnowledgeRepository(session)
        self.rule_repo = DecisionRuleRepository(session)
        self.strategy_repo = TestStrategyRepository(session)
        self.correlation_repo = VulnerabilityCorrelationRepository(session)
        self.contextual_score_repo = ContextualScoreRepository(session)
        self.adaptive_rule_repo = AdaptiveRuleRepository(session)

    async def evaluate_rule(
        self, rule: DecisionRule, target_id: Optional[int] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluate a decision rule against the current knowledge.

        Args:
            rule: The decision rule to evaluate
            target_id: Optional target ID to limit the evaluation scope

        Returns:
            Tuple of (rule_matches, result_data)
        """
        # Process rule conditions
        conditions = rule.conditions
        condition_type = conditions.get("condition_type", "")
        result_data = {}

        # Basic validation
        if not condition_type:
            logger.warning(f"Rule {rule.id} has no condition_type, skipping")
            return False, {}

        # Service detection rules
        if (
            condition_type == "service_detected"
            and rule.rule_type == DecisionRuleType.SERVICE_DETECTION
        ):
            service_type = conditions.get("service_type")
            if not service_type:
                return False, {}

            # Check if service has been detected
            if target_id:
                services_key = f"services.{service_type}"
            else:
                services_key = f"target.{target_id}.services.{service_type}"
            service_data = await self.knowledge_repo.get_value(services_key, target_id)

            if not service_data:
                return False, {}

            # Rule matches
            result_data = {
                "service_type": service_type,
                "service_data": service_data,
                "target_id": target_id,
            }
            return True, result_data

        # Vulnerability scan rules
        elif (
            condition_type == "vulnerability_scan_needed"
            and rule.rule_type == DecisionRuleType.VULNERABILITY_SCAN
        ):
            service_type = conditions.get("service_type")
            port_number = conditions.get("port_number")

            if not service_type:
                return False, {}

            # Check if services of this type exist
            services_key = (
                f"services.{service_type}"
                if target_id
                else f"target.{target_id}.services.{service_type}"
            )
            service_data = await self.knowledge_repo.get_value(services_key, target_id)

            if not service_data:
                return False, {}

            # Check if already scanned
            scanned_key = (
                f"scanned.{service_type}"
                if target_id
                else f"target.{target_id}.scanned.{service_type}"
            )
            already_scanned = await self.knowledge_repo.get_value(
                scanned_key, target_id
            )

            # If already scanned, don't scan again
            if already_scanned:
                return False, {}

            # Rule matches - should scan
            result_data = {
                "service_type": service_type,
                "service_data": service_data,
                "port_number": port_number,
                "target_id": target_id,
            }
            return True, result_data

        # Other rule types would go here

        # Default: no match
        return False, {}

    async def execute_rule_action(
        self, rule: DecisionRule, result_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the actions specified in a rule.

        Args:
            rule: The decision rule with actions to execute
            result_data: Data from rule evaluation

        Returns:
            Result of action execution
        """
        actions = rule.actions
        action_type = actions.get("action_type", "")
        action_result = {"success": False, "message": "No action taken"}

        # Basic validation
        if not action_type:
            logger.warning(f"Rule {rule.id} has no action_type, skipping")
            return action_result

        # Handle knowledge update actions
        if action_type == "update_knowledge":
            key = actions.get("knowledge_key", "")
            value = actions.get("knowledge_value")
            target_id = result_data.get("target_id")

            if key and value is not None:
                try:
                    # Add context information to the value if it's a dict
                    if isinstance(value, dict) and result_data:
                        value.update(
                            {k: v for k, v in result_data.items() if k != "target_id"}
                        )

                    # Store the knowledge
                    await self.knowledge_repo.set_value(
                        key=key,
                        value=value,
                        target_id=target_id,
                        confidence=ConfidenceLevel.MEDIUM,
                    )
                    action_result = {
                        "success": True,
                        "message": f"Updated knowledge {key}",
                        "key": key,
                        "value": value,
                    }
                except Exception as e:
                    logger.error(f"Error updating knowledge: {str(e)}")
                    action_result = {
                        "success": False,
                        "message": f"Failed to update knowledge: {str(e)}",
                    }

        # Plan vulnerability scan
        elif action_type == "plan_vulnerability_scan":
            target_id = result_data.get("target_id")
            service_type = result_data.get("service_type")

            if not target_id or not service_type:
                return {
                    "success": False,
                    "message": "Missing target or service information",
                }

            # Create a strategy for vulnerability scanning
            try:
                parameters = {
                    "target_id": target_id,
                    "service_type": service_type,
                    "scan_type": actions.get("scan_type", "standard"),
                    "parameters": actions.get("scan_parameters", {}),
                }

                job_id = await self.knowledge_repo.get_value("current_job_id")
                if not job_id:
                    return {
                        "success": False,
                        "message": "No current job ID found in knowledge base",
                    }

                # Create the test strategy
                strategy_name = f"Vulnerability scan for {service_type}"
                strategy_desc = (
                    f"Automated vulnerability scan for {service_type} service"
                )
                strategy = await self.strategy_repo.create_strategy(
                    TestStrategyCreate(
                        job_id=job_id,
                        name=strategy_name,
                        description=strategy_desc,
                        phase=StrategyPhase.VULNERABILITY_SCAN,
                        parameters=parameters,
                    )
                )

                # Add the rule to the strategy
                await self.strategy_repo.add_rule_to_strategy(strategy.id, rule.id)

                action_result = {
                    "success": True,
                    "message": f"Planned vulnerability scan for {service_type}",
                    "strategy_id": strategy.id,
                }

                # Mark as scanned in knowledge base
                scanned_key = (
                    f"scanned.{service_type}"
                    if target_id
                    else f"target.{target_id}.scanned.{service_type}"
                )
                await self.knowledge_repo.set_value(
                    key=scanned_key,
                    value=True,
                    target_id=target_id,
                )

            except Exception as e:
                logger.error(f"Error planning vulnerability scan: {str(e)}")
                action_result = {
                    "success": False,
                    "message": f"Failed to plan vulnerability scan: {str(e)}",
                }

        # Additional action types would go here

        return action_result

    async def process_rules(
        self, rule_type: DecisionRuleType, target_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Process all rules of a specific type.

        Args:
            rule_type: The type of rules to process
            target_id: Optional target ID to limit the scope

        Returns:
            List of results from rule processing
        """
        results = []
        rules = await self.rule_repo.get_rules_by_type(
            rule_type.value, active_only=True
        )

        for rule in rules:
            # Evaluate the rule
            matches, result_data = await self.evaluate_rule(rule, target_id)

            if matches:
                # Execute the rule's actions
                action_result = await self.execute_rule_action(rule, result_data)

                results.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "matched": True,
                        "action_result": action_result,
                    }
                )
            else:
                results.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "matched": False,
                    }
                )

        return results

    async def analyze_reconnaissance_results(
        self, target_id: int
    ) -> List[Dict[str, Any]]:
        """Analyze reconnaissance results and make decisions.

        Args:
            target_id: Target ID

        Returns:
            List of decision results
        """
        # First, update the knowledge base with the reconnaissance results
        # This would typically be called after reconnaissance completes

        # Then process service detection rules
        return await self.process_rules(DecisionRuleType.SERVICE_DETECTION, target_id)

    async def plan_vulnerability_scans(self, target_id: int) -> List[Dict[str, Any]]:
        """Plan vulnerability scans based on reconnaissance results.

        Args:
            target_id: Target ID

        Returns:
            List of vulnerability scan plans
        """
        return await self.process_rules(DecisionRuleType.VULNERABILITY_SCAN, target_id)

    async def formulate_strategy(self, job_id: int) -> List[TestStrategy]:
        """Formulate an overall testing strategy.

        Args:
            job_id: Job ID

        Returns:
            List of test strategies
        """
        # Get all targets for this job
        target_ids = await self.knowledge_repo.get_value(f"job.{job_id}.targets")
        if not target_ids:
            logger.warning(f"No targets found for job {job_id}")
            return []

        await self.knowledge_repo.set_value("current_job_id", job_id)

        # For each target, analyze reconnaissance results
        for target_id in target_ids:
            # Process service detection rules
            await self.analyze_reconnaissance_results(target_id)

            # Plan vulnerability scans
            await self.plan_vulnerability_scans(target_id)

        # Get all strategies created for this job
        return await self.strategy_repo.get_strategies_by_job(job_id)

    async def initialize_default_rules(self) -> List[DecisionRule]:
        """Initialize default decision rules.

        Returns:
            List of created rules
        """
        default_rules = []

        # Service detection rules for common services
        service_types = [
            (ServiceType.HTTP, "HTTP"),
            (ServiceType.HTTPS, "HTTPS"),
            (ServiceType.SSH, "SSH"),
            (ServiceType.FTP, "FTP"),
            (ServiceType.SMTP, "SMTP"),
            (ServiceType.MYSQL, "MySQL"),
            (ServiceType.POSTGRESQL, "PostgreSQL"),
        ]

        for service_type, name in service_types:
            # Create a rule to detect the service
            detection_rule = await self.rule_repo.create_rule(
                DecisionRuleCreate(
                    name=f"Detect {name} service",
                    description=(
                        f"Detects when {name} service is found during reconnaissance"
                    ),
                    rule_type=DecisionRuleType.SERVICE_DETECTION,
                    severity=DecisionRuleSeverity.MEDIUM,
                    conditions={
                        "condition_type": "service_detected",
                        "service_type": service_type.value,
                    },
                    actions={
                        "action_type": "update_knowledge",
                        "knowledge_key": f"services.{service_type.value}",
                        "knowledge_value": {
                            "detected": True,
                            "timestamp": "now",
                        },
                    },
                    priority=100,
                )
            )
            default_rules.append(detection_rule)

            # Create a rule to plan vulnerability scan for the service
            scan_rule = await self.rule_repo.create_rule(
                DecisionRuleCreate(
                    name=f"Plan {name} vulnerability scan",
                    description=(
                        f"Plans a vulnerability scan for detected {name} services"
                    ),
                    rule_type=DecisionRuleType.VULNERABILITY_SCAN,
                    severity=DecisionRuleSeverity.MEDIUM,
                    conditions={
                        "condition_type": "vulnerability_scan_needed",
                        "service_type": service_type.value,
                    },
                    actions={
                        "action_type": "plan_vulnerability_scan",
                        "scan_type": "standard",
                        "scan_parameters": {
                            "depth": "standard",
                            "timeout": 300,
                        },
                    },
                    priority=200,
                )
            )
            default_rules.append(scan_rule)

        return default_rules

    async def analyze_vulnerability_prioritization(
        self, target_id: int, job_id: int
    ) -> Optional[TestStrategy]:
        """Analyze vulnerabilities and create a test strategy based on prioritization.

        Args:
            target_id: The target ID to analyze vulnerabilities for
            job_id: The job ID associated with the test strategy

        Returns:
            Created test strategy or None if no vulnerabilities found
        """
        # Create vulnerability scanner service
        vuln_service = VulnerabilityScannerService(self.session)

        # Get prioritized vulnerabilities
        prioritized_vulns = await vuln_service.prioritize_target_vulnerabilities(
            target_id=target_id, include_business_impact=True
        )

        if not prioritized_vulns:
            logger.info(f"No vulnerabilities found for target {target_id}")
            return None

        # Extract top vulnerabilities (up to 5)
        top_vulns = prioritized_vulns[:5]

        # Prepare test strategy parameters
        parameters = {
            "prioritized_vulnerabilities": [
                {
                    "id": vuln.id,
                    "name": vuln.name,
                    "severity": vuln.severity.value,
                    "priority_score": score,
                    "affected_component": vuln.affected_component,
                    "status": vuln.status.value,
                }
                for vuln, score in top_vulns
            ],
            "target_id": target_id,
            "strategy_approach": "prioritized_testing",
        }

        # Create test strategy based on vulnerability prioritization
        strategy_data = TestStrategyCreate(
            job_id=job_id,
            name="Prioritized Vulnerability Testing",
            description="Test strategy based on vulnerability prioritization algorithm",
            phase=StrategyPhase.EXPLOITATION,
            parameters=parameters,
            is_active=True,
            priority=50,  # Higher priority than default strategies
        )

        strategy = await self.strategy_repo.create_strategy(strategy_data)
        logger.info(
            f"Created prioritized vulnerability testing strategy {strategy.id} "
            f"with {len(top_vulns)} prioritized vulnerabilities"
        )

        return strategy

    async def create_vulnerability_based_rules(
        self, prioritized_vulnerabilities: List[Tuple[Vulnerability, float]]
    ) -> List[DecisionRule]:
        """
        Create decision rules based on prioritized vulnerabilities.

        Args:
            prioritized_vulnerabilities: List of tuples containing vulnerabilities and their priority scores

        Returns:
            List of created decision rules
        """
        rules = []

        # Get top vulnerabilities (high priority)
        top_vulnerabilities = prioritized_vulnerabilities[:5]

        if not top_vulnerabilities:
            return []

        # Create a rule for critical/high vulnerabilities
        high_priority_vulns = [
            v
            for v, score in top_vulnerabilities
            if v.severity
            in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH)
        ]

        if high_priority_vulns:
            # Create a rule for high priority vulnerabilities
            high_rule = await self.rule_repo.create_rule(
                DecisionRuleCreate(
                    name="Focus on Critical Vulnerabilities",
                    description=(
                        "Prioritize testing for critical and high severity vulnerabilities"
                    ),
                    rule_type=DecisionRuleType.EXPLOITATION,
                    severity=DecisionRuleSeverity.CRITICAL,
                    conditions={
                        "vulnerability_ids": [v.id for v in high_priority_vulns],
                        "min_priority_score": 0.7,
                    },
                    actions={
                        "test_priority": "high",
                        "suggested_tools": [
                            "manual_testing",
                            "specialized_scanner",
                        ],
                        "suggested_techniques": [
                            "deep_inspection",
                            "exploit_verification",
                        ],
                    },
                    metadata={
                        "vulnerability_count": len(high_priority_vulns),
                        "average_cvss": (
                            sum(v.cvss_score or 0 for v in high_priority_vulns)
                            / len(high_priority_vulns)
                            if high_priority_vulns
                            else 0
                        ),
                    },
                )
            )
            rules.append(high_rule)

        # Create a rule for medium/low vulnerabilities with specific patterns
        medium_low_vulns = [
            v
            for v, score in prioritized_vulnerabilities
            if v.severity in (VulnerabilitySeverity.MEDIUM, VulnerabilitySeverity.LOW)
        ][
            :10
        ]  # Limit to 10

        if medium_low_vulns:
            # Group by type/pattern
            grouped_vulns: Dict[str, List[Vulnerability]] = {}
            for vuln in medium_low_vulns:
                vuln_type = vuln.name.split()[0] if vuln.name else "Unknown"
                if vuln_type not in grouped_vulns:
                    grouped_vulns[vuln_type] = []
                grouped_vulns[vuln_type].append(vuln)

            # Find the most common type
            if grouped_vulns:
                most_common_type = max(grouped_vulns.items(), key=lambda x: len(x[1]))[
                    0
                ]
                common_vulns = grouped_vulns[most_common_type]

                if len(common_vulns) >= 2:  # If we have at least 2 of the same type
                    pattern_rule = await self.rule_repo.create_rule(
                        DecisionRuleCreate(
                            name=f"Check for {most_common_type} Patterns",
                            description=(
                                f"Multiple {most_common_type} vulnerabilities detected. "
                                "Test for similar patterns."
                            ),
                            rule_type=DecisionRuleType.EXPLOITATION,
                            severity=DecisionRuleSeverity.MEDIUM,
                            conditions={
                                "vulnerability_ids": [v.id for v in common_vulns],
                                "vulnerability_type": most_common_type,
                            },
                            actions={
                                "test_priority": "medium",
                                "suggested_tools": [
                                    "automated_scanner",
                                    "pattern_analysis",
                                ],
                                "suggested_techniques": [
                                    "pattern_testing",
                                    "broad_coverage",
                                ],
                            },
                            metadata={
                                "pattern_type": most_common_type,
                                "vulnerability_count": len(common_vulns),
                            },
                        )
                    )
                    rules.append(pattern_rule)

        return rules

    async def analyze_vulnerability_correlations(
        self, target_id: int
    ) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities for correlation patterns.

        Identifies compound risks and vulnerability relationships that may
        have higher combined impact than individual vulnerabilities.

        Args:
            target_id: Target ID to analyze

        Returns:
            List of correlation analysis results
        """
        # Get all vulnerabilities for the target
        vuln_repo = VulnerabilityRepository(self.session)
        vulnerabilities = await vuln_repo.get_vulnerabilities_by_target(target_id)

        # Get active correlation patterns
        correlation_patterns = await self.correlation_repo.get_active_correlations()

        results = []

        for pattern in correlation_patterns:
            # Apply the correlation pattern to identify related vulnerabilities
            matched_vulnerabilities = await self._apply_correlation_pattern(
                pattern, vulnerabilities
            )

            if matched_vulnerabilities:
                # Calculate adjusted severity based on the correlation
                adjusted_severity = self._calculate_correlated_severity(
                    matched_vulnerabilities, pattern
                )

                # Create correlation result
                correlation_result = {
                    "correlation_id": pattern.id,
                    "correlation_name": pattern.name,
                    "matched_vulnerabilities": [v.id for v in matched_vulnerabilities],
                    "adjusted_severity": adjusted_severity,
                    "context_type": pattern.context_type.value,
                    "confidence": pattern.confidence.value,
                    "timestamp": datetime.utcnow().isoformat(),
                }

                # Store correlation in knowledge base
                correlation_key = f"correlations.{pattern.id}.target_{target_id}"
                await self.knowledge_repo.set_value(
                    key=correlation_key,
                    value=correlation_result,
                    target_id=target_id,
                    confidence=pattern.confidence,
                )

                results.append(correlation_result)

                # Create a decision rule based on the correlation if severe enough
                if adjusted_severity >= 0.8:  # High severity threshold
                    await self._create_correlation_rule(
                        pattern, matched_vulnerabilities, adjusted_severity
                    )

        return results

    async def _apply_correlation_pattern(
        self, pattern: VulnerabilityCorrelation, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Apply a correlation pattern to a list of vulnerabilities.

        Args:
            pattern: Correlation pattern to apply
            vulnerabilities: List of vulnerabilities to check

        Returns:
            List of matched vulnerabilities
        """
        pattern_def = pattern.pattern_definition
        pattern_type = pattern.pattern_type
        matched_vulnerabilities = []

        if pattern_type == "component_chain":
            # Pattern that looks for vulnerabilities in connected components
            components = pattern_def.get("components", [])
            component_match_map: Dict[str, List[Any]] = {
                component: [] for component in components
            }

            # Group vulnerabilities by component
            for vuln in vulnerabilities:
                component = vuln.affected_component
                if component and any(c in component for c in components):
                    for target_comp in components:
                        if target_comp in component:
                            component_match_map[target_comp].append(vuln)

            # Check if we have matches for all components in the chain
            if all(len(matches) > 0 for matches in component_match_map.values()):
                # Add all matching vulnerabilities
                for matches in component_match_map.values():
                    matched_vulnerabilities.extend(matches)

        elif pattern_type == "multi_vulnerability":
            # Pattern that looks for multiple types of vulnerabilities
            required_types = pattern_def.get("vulnerability_types", [])
            severity_threshold = pattern_def.get("min_severity", "LOW")

            # Group vulnerabilities by type
            vuln_type_map: Dict[str, List[Any]] = {}
            for vuln in vulnerabilities:
                # Extract vulnerability type from name
                vuln_type = re.split(r"\s+", vuln.name)[0].lower() if vuln.name else ""

                # Use affected component as fallback
                if not vuln_type and vuln.affected_component:
                    vuln_type = vuln.affected_component.split()[0].lower()

                # Check if this vulnerability matches any required type
                for req_type in required_types:
                    if req_type.lower() in vuln.name.lower():
                        if req_type not in vuln_type_map:
                            vuln_type_map[req_type] = []
                        vuln_type_map[req_type].append(vuln)

            # Check if we have all required vulnerability types with sufficient severity
            if all(req_type in vuln_type_map for req_type in required_types):
                for req_type in required_types:
                    # Filter by severity threshold
                    severity_matches = [
                        v
                        for v in vuln_type_map[req_type]
                        if self._severity_to_value(v.severity)
                        >= self._severity_to_value(
                            VulnerabilitySeverity(severity_threshold)
                        )
                    ]
                    if severity_matches:
                        matched_vulnerabilities.extend(severity_matches)

        elif pattern_type == "temporal_sequence":
            # Pattern that looks for vulnerabilities in a specific temporal sequence
            # For MVP, we just check if all required vulnerability types exist
            required_sequence = pattern_def.get("sequence", [])
            if required_sequence:
                # Group by vulnerability type
                type_matches: Dict[str, List[Any]] = {}
                for step in required_sequence:
                    type_matches[step] = []

                for vuln in vulnerabilities:
                    for step in required_sequence:
                        if step.lower() in vuln.name.lower():
                            type_matches[step].append(vuln)

                # Check if we have matches for all steps in the sequence
                if all(len(matches) > 0 for matches in type_matches.values()):
                    # Add all matching vulnerabilities
                    for matches in type_matches.values():
                        matched_vulnerabilities.extend(matches)

        return matched_vulnerabilities

    def _calculate_correlated_severity(
        self, vulnerabilities: List[Vulnerability], pattern: VulnerabilityCorrelation
    ) -> float:
        """Calculate severity for correlated vulnerabilities.

        Args:
            vulnerabilities: List of related vulnerabilities
            pattern: Correlation pattern applied

        Returns:
            Adjusted severity score (0.0-1.0)
        """
        if not vulnerabilities:
            return 0.0

        # Convert vulnerability severities to numerical values (0.0-1.0)
        severity_values = [self._severity_to_value(v.severity) for v in vulnerabilities]

        # Calculate base severity (average of individual severities)
        base_severity = sum(severity_values) / len(severity_values)

        # Apply pattern's severity adjustment
        adjusted_severity = base_severity * pattern.severity_adjustment

        # Cap at 1.0
        return float(min(adjusted_severity, 1.0))

    def _severity_to_value(self, severity: VulnerabilitySeverity) -> float:
        """Convert severity enum to numerical value.

        Args:
            severity: Vulnerability severity enum

        Returns:
            Numerical value (0.0-1.0)
        """
        severity_map = {
            VulnerabilitySeverity.LOW: 0.25,
            VulnerabilitySeverity.MEDIUM: 0.5,
            VulnerabilitySeverity.HIGH: 0.75,
            VulnerabilitySeverity.CRITICAL: 1.0,
        }
        return severity_map.get(severity, 0.25)

    async def _create_correlation_rule(
        self,
        pattern: VulnerabilityCorrelation,
        vulnerabilities: List[Vulnerability],
        severity: float,
    ) -> Optional[DecisionRule]:
        """Create a decision rule based on a correlation pattern.

        Args:
            pattern: Correlation pattern
            vulnerabilities: Matched vulnerabilities
            severity: Adjusted severity score

        Returns:
            Created decision rule or None if not created
        """
        # Determine rule severity based on adjusted severity
        rule_severity = DecisionRuleSeverity.MEDIUM
        if severity >= 0.9:
            rule_severity = DecisionRuleSeverity.CRITICAL
        elif severity >= 0.7:
            rule_severity = DecisionRuleSeverity.HIGH
        elif severity < 0.3:
            rule_severity = DecisionRuleSeverity.LOW

        # Create rule data
        rule_data = DecisionRuleCreate(
            name=f"Correlated: {pattern.name}",
            description=(
                f"Rule created from correlation pattern: {pattern.description}. "
                f"Affects {len(vulnerabilities)} vulnerabilities."
            ),
            rule_type=DecisionRuleType.CORRELATION,
            severity=rule_severity,
            conditions={
                "correlation_pattern_id": pattern.id,
                "vulnerability_ids": [v.id for v in vulnerabilities],
                "min_severity": rule_severity.value,
            },
            actions={
                "test_priority": "high" if severity >= 0.7 else "medium",
                "suggested_approach": "correlated_assessment",
                "consolidate_vulnerabilities": True,
            },
            is_active=True,
            priority=int(
                100 - severity * 50
            ),  # Higher severity = higher priority (lower number)
            metadata={
                "correlation_type": pattern.pattern_type,
                "context_type": pattern.context_type.value,
                "adjusted_severity": severity,
                "vulnerability_count": len(vulnerabilities),
                "created_from_correlation": True,
            },
        )

        try:
            return await self.rule_repo.create_rule(rule_data)
        except Exception as e:
            logger.error(f"Error creating correlation rule: {str(e)}")
            return None

    async def apply_contextual_scoring(
        self, vulnerabilities: List[Vulnerability], target_id: int
    ) -> List[Tuple[Vulnerability, float]]:
        """Apply contextual scoring to vulnerabilities based on environment.

        Args:
            vulnerabilities: List of vulnerabilities to score
            target_id: Target ID for context

        Returns:
            List of (vulnerability, adjusted_score) tuples
        """
        # Get target information for context
        target_repo = TargetRepository(self.session)
        target = await target_repo.get_target(target_id)

        if not target or not vulnerabilities:
            return [(v, self._severity_to_value(v.severity)) for v in vulnerabilities]

        # Get active contextual scoring rules
        scoring_rules = await self.contextual_score_repo.get_active_scores()

        # Target metadata for context analysis
        target_metadata = target.target_metadata or {}

        # Initialize with base scores
        scored_vulnerabilities = [
            (v, self._severity_to_value(v.severity)) for v in vulnerabilities
        ]

        # Apply each scoring rule
        for rule in scoring_rules:
            # Check if this context applies to the target
            if not self._context_applies_to_target(rule, target):
                continue

            # Apply scoring adjustments
            scored_vulnerabilities = [
                (v, self._apply_context_score(v, score, rule, target_metadata))
                for v, score in scored_vulnerabilities
            ]

        return scored_vulnerabilities

    def _context_applies_to_target(
        self, score_rule: ContextualScore, target: Target
    ) -> bool:
        """Check if a contextual scoring rule applies to a target.

        Args:
            score_rule: Contextual scoring rule
            target: Target to check

        Returns:
            True if the rule applies to this target
        """
        context_def = score_rule.context_definition
        target_metadata = target.target_metadata or {}

        # Check if target matches environment criteria
        if "environments" in context_def:
            target_env = target_metadata.get("environment", "").lower()
            rule_envs = [env.lower() for env in context_def["environments"]]
            if not target_env or target_env not in rule_envs:
                return False

        # Check if target matches criticality criteria
        if "criticality" in context_def:
            target_criticality = target_metadata.get("criticality", "").lower()
            rule_criticalities = [crit.lower() for crit in context_def["criticality"]]
            if not target_criticality or target_criticality not in rule_criticalities:
                return False

        # Check if target matches business unit criteria
        if "business_units" in context_def:
            target_bu = target_metadata.get("business_unit", "").lower()
            rule_bus = [bu.lower() for bu in context_def["business_units"]]
            if not target_bu or target_bu not in rule_bus:
                return False

        return True

    def _apply_context_score(
        self,
        vulnerability: Vulnerability,
        base_score: float,
        score_rule: ContextualScore,
        target_metadata: Dict[str, Any],
    ) -> float:
        """Apply contextual scoring to a vulnerability.

        Args:
            vulnerability: Vulnerability to score
            base_score: Base severity score (0.0-1.0)
            score_rule: Contextual scoring rule
            target_metadata: Target metadata for context

        Returns:
            Adjusted severity score (0.0-1.0)
        """
        scoring_function = score_rule.scoring_function
        function_type = scoring_function.get("type", "multiply")

        # Get the score adjustment value
        adjustment = scoring_function.get("value", 1.0)

        # Check for conditional adjustments
        if "conditions" in scoring_function:
            conditions = scoring_function["conditions"]

            # Check environment-specific conditions
            if "environment" in conditions:
                env_conditions = conditions["environment"]
                target_env = target_metadata.get("environment", "").lower()

                if target_env and target_env in env_conditions:
                    env_adjustment = env_conditions[target_env]
                    if isinstance(env_adjustment, (int, float)):
                        adjustment = env_adjustment

            # Check vulnerability-specific conditions
            if "vulnerability_type" in conditions:
                vuln_conditions = conditions["vulnerability_type"]

                # Extract vuln type from name or component
                vuln_type = None
                if vulnerability.name:
                    vuln_type = vulnerability.name.split()[0].lower()
                elif vulnerability.affected_component:
                    vuln_type = vulnerability.affected_component.split()[0].lower()

                if vuln_type and vuln_type in vuln_conditions:
                    vuln_adjustment = vuln_conditions[vuln_type]
                    if isinstance(vuln_adjustment, (int, float)):
                        adjustment = vuln_adjustment

        # Apply the adjustment according to function type
        if function_type == "multiply":
            adjusted_score = base_score * adjustment
        elif function_type == "add":
            adjusted_score = base_score + adjustment
        elif function_type == "max":
            adjusted_score = max(base_score, adjustment)
        elif function_type == "min":
            adjusted_score = min(base_score, adjustment)
        else:
            adjusted_score = base_score

        # Cap at range 0.0-1.0
        return float(max(0.0, min(adjusted_score, 1.0)))

    async def create_contextual_scoring_rule(
        self, rule_data: ContextualScoreCreate
    ) -> ContextualScore:
        """Create a new contextual scoring rule.

        Args:
            rule_data: Contextual scoring rule data

        Returns:
            Created contextual score rule
        """
        return await self.contextual_score_repo.create_score(rule_data)

    async def create_correlation_pattern(
        self, pattern_data: VulnerabilityCorrelationCreate
    ) -> VulnerabilityCorrelation:
        """Create a new vulnerability correlation pattern.

        Args:
            pattern_data: Vulnerability correlation pattern data

        Returns:
            Created correlation pattern
        """
        return await self.correlation_repo.create_correlation(pattern_data)

    async def evaluate_and_adapt_rules(
        self,
        job_id: int,
        target_id: int,
        successful_rules: Optional[List[int]] = None,
        failed_rules: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluate rule effectiveness and adapt rules based on feedback.

        Args:
            job_id: Job ID
            target_id: Target ID
            successful_rules: List of rule IDs that were successful
            failed_rules: List of rule IDs that failed

        Returns:
            List of adaptation results
        """
        results = []
        successful_rules = successful_rules or []
        failed_rules = failed_rules or []

        # Update existing adaptive rules with success/failure feedback
        for rule_id in successful_rules:
            rule = await self.adaptive_rule_repo.get_adaptive_rule(rule_id)
            if rule:
                updated_rule = await self.adaptive_rule_repo.update_rule_effectiveness(
                    rule_id=rule_id, success=True
                )
                if updated_rule:
                    results.append(
                        {
                            "rule_id": rule_id,
                            "action": "updated",
                            "success": True,
                            "effectiveness": updated_rule.effectiveness_score,
                        }
                    )

        for rule_id in failed_rules:
            rule = await self.adaptive_rule_repo.get_adaptive_rule(rule_id)
            if rule:
                updated_rule = await self.adaptive_rule_repo.update_rule_effectiveness(
                    rule_id=rule_id, success=False
                )
                if updated_rule:
                    results.append(
                        {
                            "rule_id": rule_id,
                            "action": "updated",
                            "success": True,
                            "effectiveness": updated_rule.effectiveness_score,
                        }
                    )

                    # If rule effectiveness falls below threshold, evolve the rule
                    if (
                        updated_rule.effectiveness_score < 0.4
                        and updated_rule.failure_count >= 3
                    ):
                        await self._evolve_ineffective_rule(updated_rule)
                        results.append(
                            {
                                "rule_id": rule_id,
                                "action": "evolved",
                                "success": True,
                                "reason": "Low effectiveness",
                            }
                        )

        # Convert standard rules to adaptive rules for high-value targets
        target_repo = TargetRepository(self.session)
        target = await target_repo.get_target(target_id)

        if (
            target
            and target.target_metadata
            and target.target_metadata.get("criticality") == "high"
        ):
            # Get standard rules that were used for this target/job
            strategies = await self.strategy_repo.get_strategies_by_job(job_id)
            for strategy in strategies:
                # For each rule in the strategy, convert to adaptive if valuable
                for rule_item in strategy.rules:
                    # Skip if already an adaptive rule
                    # Ensure rule has an id attribute
                    if not hasattr(rule_item, "id"):
                        continue

                    rule_id = rule_item.id  # type: ignore
                    existing_adaptive = (
                        await self.adaptive_rule_repo.get_adaptive_rules_by_base_rule(
                            rule_id
                        )
                    )
                    if existing_adaptive:
                        continue

                    # Convert high-severity rules to adaptive for continued improvement
                    # Ensure rule has a severity attribute
                    if not hasattr(rule_item, "severity"):
                        continue

                    rule_severity = rule_item.severity  # type: ignore
                    if rule_severity in (
                        DecisionRuleSeverity.HIGH,
                        DecisionRuleSeverity.CRITICAL,
                    ):
                        # Only pass DecisionRule to _convert_to_adaptive_rule
                        if isinstance(rule_item, DecisionRule):
                            adaptive_rule_result = await self._convert_to_adaptive_rule(
                                rule_item
                            )
                            if adaptive_rule_result is not None:
                                results.append(
                                    {
                                        "base_rule_id": rule_id,
                                        "adaptive_rule_id": adaptive_rule_result.id,
                                        "action": "converted",
                                        "success": True,
                                    }
                                )
                        else:
                            # Log that we couldn't convert a non-DecisionRule
                            logger.warning(
                                "Could not convert rule to adaptive: not a DecisionRule type"
                            )

        return results

    async def _evolve_ineffective_rule(
        self, rule: AdaptiveRule
    ) -> Optional[AdaptiveRule]:
        """Evolve an ineffective rule to improve performance.

        Args:
            rule: Adaptive rule to evolve

        Returns:
            Evolved rule or None if evolution failed
        """
        # Initialize modifications dictionary
        modifications: Dict[str, Any] = {}

        if rule.rule_type == DecisionRuleType.VULNERABILITY_SCAN:
            # Make vulnerability scan conditions more specific
            if "service_type" in rule.conditions:
                # Add more specific scan parameters
                scan_params = {
                    "scan_parameters": {
                        "depth": "deep",
                        "timeout": 600,
                        "include_advanced_checks": True,
                    }
                }
                modifications["actions"] = json.dumps(scan_params)

        elif rule.rule_type == DecisionRuleType.CORRELATION:
            # For correlation rules, lower the threshold to be more inclusive
            if "min_severity" in rule.conditions:
                current_severity = rule.conditions["min_severity"]
                if current_severity == "CRITICAL":
                    # Create or update the conditions dictionary
                    conditions_dict: Dict[str, Any] = {}
                    if "conditions" in modifications:
                        if isinstance(modifications["conditions"], dict):
                            conditions_dict = modifications["conditions"]
                    conditions_dict["min_severity"] = "HIGH"
                    modifications["conditions"] = conditions_dict
                elif current_severity == "HIGH":
                    # Create or update the conditions dictionary
                    high_conditions_dict: Dict[str, Any] = {}
                    if "conditions" in modifications:
                        if isinstance(modifications["conditions"], dict):
                            high_conditions_dict = modifications["conditions"]
                    high_conditions_dict["min_severity"] = "MEDIUM"
                    modifications["conditions"] = high_conditions_dict

        # Create an evolved rule with these modifications
        try:
            return await self.adaptive_rule_repo.create_evolved_rule(
                rule.id, modifications
            )
        except Exception as e:
            logger.error(f"Error evolving rule: {str(e)}")
            return None

    async def _convert_to_adaptive_rule(
        self, rule: DecisionRule
    ) -> Optional[AdaptiveRule]:
        """Convert a standard decision rule to an adaptive rule.

        Args:
            rule: Standard decision rule to convert

        Returns:
            Created adaptive rule or None if creation failed
        """
        rule_data = AdaptiveRuleCreate(
            base_rule_id=rule.id,
            name=f"Adaptive: {rule.name}",
            description=f"Adaptive version of: {rule.description}",
            rule_type=rule.rule_type,
            conditions=dict(rule.conditions),
            actions=dict(rule.actions),
            confidence=ConfidenceLevel.MEDIUM,
            is_active=True,
            metadata={
                "converted_from_standard_rule": True,
                "original_rule_id": rule.id,
                "creation_reason": "High-value target optimization",
            },
        )

        try:
            return await self.adaptive_rule_repo.create_adaptive_rule(rule_data)
        except Exception as e:
            logger.error(f"Error converting to adaptive rule: {str(e)}")
            return None

    async def enhance_vulnerability_prioritization(
        self, target_id: int, job_id: int
    ) -> Optional[TestStrategy]:
        """Enhanced version of vulnerability prioritization with correlation and context.

        This is an advanced version of the analyze_vulnerability_prioritization method
        that incorporates vulnerability correlation and contextual scoring.

        Args:
            target_id: The target ID to analyze vulnerabilities for
            job_id: The job ID associated with the test strategy

        Returns:
            Created test strategy or None if no vulnerabilities found
        """
        # Get vulnerability scanner service
        vuln_repo = VulnerabilityRepository(self.session)

        # Get all vulnerabilities for the target
        vulnerabilities = await vuln_repo.get_vulnerabilities_by_target(target_id)

        if not vulnerabilities:
            logger.info(f"No vulnerabilities found for target {target_id}")
            return None

        # Step 1: Apply contextual scoring
        contextualized_vulns = await self.apply_contextual_scoring(
            vulnerabilities, target_id
        )

        # Step 2: Apply vulnerability correlation analysis
        correlations = await self.analyze_vulnerability_correlations(target_id)

        # Adjust scores based on correlations
        if correlations:
            # Create a map of vulnerability IDs to correlation-adjusted scores
            correlation_scores: Dict[int, float] = {}
            for correlation in correlations:
                adjusted_severity = correlation.get("adjusted_severity", 0.5)
                for vuln_id in correlation.get("matched_vulnerabilities", []):
                    # Use the highest correlation severity for each vulnerability
                    if (
                        vuln_id not in correlation_scores
                        or adjusted_severity > correlation_scores[vuln_id]
                    ):
                        correlation_scores[vuln_id] = adjusted_severity

            # Apply correlation adjustments to scores
            adjusted_vulns = []
            for vuln, score in contextualized_vulns:
                if vuln.id in correlation_scores:
                    # Boost score for correlated vulnerabilities
                    adjusted_score = max(score, correlation_scores[vuln.id])
                    adjusted_vulns.append((vuln, adjusted_score))
                else:
                    adjusted_vulns.append((vuln, score))

            contextualized_vulns = adjusted_vulns

        # Sort by adjusted score (descending)
        prioritized_vulns = sorted(
            contextualized_vulns, key=lambda x: x[1], reverse=True
        )

        # Extract top vulnerabilities (up to 5)
        top_vulns = prioritized_vulns[:5]

        # Prepare test strategy parameters
        parameters = {
            "prioritized_vulnerabilities": [
                {
                    "id": vuln.id,
                    "name": vuln.name,
                    "severity": vuln.severity.value,
                    "priority_score": score,
                    "adjusted_score": score,  # Include the adjusted score
                    "affected_component": vuln.affected_component,
                    "status": vuln.status.value,
                }
                for vuln, score in top_vulns
            ],
            "target_id": target_id,
            "strategy_approach": "enhanced_prioritization",
            "applied_correlations": [c["correlation_id"] for c in correlations],
            "correlation_count": len(correlations),
        }

        # Create enhanced test strategy
        strategy_data = TestStrategyCreate(
            job_id=job_id,
            name="Enhanced Vulnerability Assessment Strategy",
            description="Advanced strategy using correlation and contextual analysis",
            phase=StrategyPhase.EXPLOITATION,
            parameters=parameters,
            is_active=True,
            priority=30,  # Higher priority than standard strategy
            metadata={
                "enhanced_strategy": True,
                "correlation_count": len(correlations),
                "contextual_scoring": True,
            },
        )

        strategy = await self.strategy_repo.create_strategy(strategy_data)
        logger.info(
            f"Created enhanced vulnerability assessment strategy {strategy.id} "
            f"with {len(top_vulns)} prioritized vulnerabilities and {len(correlations)} correlations"
        )

        # Create decision rules for the top vulnerabilities
        await self.create_vulnerability_based_rules(top_vulns)

        return strategy

    async def initialize_default_correlation_patterns(
        self,
    ) -> List[VulnerabilityCorrelation]:
        """Initialize default vulnerability correlation patterns.

        Returns:
            List of created correlation patterns
        """
        default_patterns = []

        # Pattern 1: Web application multi-layer vulnerability chain
        web_app_pattern = await self.correlation_repo.create_correlation(
            VulnerabilityCorrelationCreate(
                name="Web Application Attack Chain",
                description="Correlates web vulnerabilities that could create an attack chain",
                pattern_type="component_chain",
                pattern_definition={
                    "components": ["web server", "application server", "database"],
                    "min_matches": 2,
                },
                severity_adjustment=1.5,  # Increase severity due to potential chaining
                confidence=ConfidenceLevel.MEDIUM,
                context_type=ContextType.APPLICATION,
                is_active=True,
                metadata={
                    "attack_type": "chained_compromise",
                    "notes": "Web application attack chains can lead to complete system compromise",
                },
            )
        )
        default_patterns.append(web_app_pattern)

        # Pattern 2: Authentication + Authorization multi-vulnerability pattern
        auth_pattern = await self.correlation_repo.create_correlation(
            VulnerabilityCorrelationCreate(
                name="Authentication-Authorization Weakness Chain",
                description="Correlates authentication and authorization vulnerabilities",
                pattern_type="multi_vulnerability",
                pattern_definition={
                    "vulnerability_types": ["Authentication", "Authorization"],
                    "min_severity": "MEDIUM",
                },
                severity_adjustment=1.75,  # Significant increase in severity
                confidence=ConfidenceLevel.HIGH,
                context_type=ContextType.USER,
                is_active=True,
                metadata={
                    "attack_type": "privilege_escalation",
                    "notes": "Combined auth flaws can lead to complete access control bypass",
                },
            )
        )
        default_patterns.append(auth_pattern)

        # Pattern 3: Injection vulnerability sequence
        injection_pattern = await self.correlation_repo.create_correlation(
            VulnerabilityCorrelationCreate(
                name="Multi-Injection Vulnerability Pattern",
                description="Correlates multiple injection-type vulnerabilities",
                pattern_type="multi_vulnerability",
                pattern_definition={
                    "vulnerability_types": [
                        "SQL Injection",
                        "Command Injection",
                        "XSS",
                    ],
                    "min_matches": 2,
                },
                severity_adjustment=1.5,
                confidence=ConfidenceLevel.MEDIUM,
                context_type=ContextType.APPLICATION,
                is_active=True,
                metadata={
                    "attack_type": "data_exfiltration",
                    "notes": "Multiple injection vulnerabilities increase likelihood of data compromise",
                },
            )
        )
        default_patterns.append(injection_pattern)

        # Pattern 4: Infrastructure exposure pattern
        infrastructure_pattern = await self.correlation_repo.create_correlation(
            VulnerabilityCorrelationCreate(
                name="Critical Infrastructure Exposure Pattern",
                description="Correlates vulnerabilities exposing critical infrastructure services",
                pattern_type="component_chain",
                pattern_definition={
                    "components": ["firewall", "router", "switch", "load balancer"],
                    "min_matches": 2,
                },
                severity_adjustment=1.8,
                confidence=ConfidenceLevel.HIGH,
                context_type=ContextType.INFRASTRUCTURE,
                is_active=True,
                metadata={
                    "attack_type": "infrastructure_compromise",
                    "notes": "Multiple infrastructure vulnerabilities can lead to widespread network compromise",
                },
            )
        )
        default_patterns.append(infrastructure_pattern)

        return default_patterns

    async def initialize_default_contextual_scores(self) -> List[ContextualScore]:
        """Initialize default contextual scoring rules.

        Returns:
            List of created contextual scoring rules
        """
        default_scores = []

        # Score 1: Production environment scoring boost
        prod_score = await self.contextual_score_repo.create_score(
            ContextualScoreCreate(
                name="Production Environment Impact",
                description="Increases severity for vulnerabilities in production environments",
                context_type=ContextType.INFRASTRUCTURE,
                context_definition={
                    "environments": ["production", "prod"],
                    "criticality": ["high", "critical"],
                },
                scoring_function={
                    "type": "multiply",
                    "value": 1.5,
                    "conditions": {
                        "environment": {
                            "production": 1.5,
                            "prod": 1.5,
                        },
                        "vulnerability_type": {
                            "authentication": 1.8,
                            "authorization": 1.8,
                            "rce": 2.0,
                            "sql": 1.7,
                        },
                    },
                },
                is_active=True,
                metadata={
                    "rationale": "Production vulnerabilities present immediate business risk",
                },
            )
        )
        default_scores.append(prod_score)

        # Score 2: Database server context scoring
        db_score = await self.contextual_score_repo.create_score(
            ContextualScoreCreate(
                name="Database Server Risk Context",
                description="Adjusts severity based on database server context",
                context_type=ContextType.DATA,
                context_definition={
                    "server_types": ["database", "db", "sql", "nosql"],
                },
                scoring_function={
                    "type": "multiply",
                    "value": 1.4,
                    "conditions": {
                        "vulnerability_type": {
                            "injection": 1.8,
                            "authentication": 1.6,
                            "encryption": 1.7,
                        }
                    },
                },
                is_active=True,
                metadata={
                    "rationale": "Database servers often contain sensitive information",
                },
            )
        )
        default_scores.append(db_score)

        # Score 3: Financial business unit context
        finance_score = await self.contextual_score_repo.create_score(
            ContextualScoreCreate(
                name="Financial Business Unit Context",
                description="Adjusts severity for financial business units",
                context_type=ContextType.BUSINESS,
                context_definition={
                    "business_units": ["finance", "accounting", "treasury", "payment"],
                    "criticality": ["high", "critical"],
                },
                scoring_function={
                    "type": "multiply",
                    "value": 1.6,
                },
                is_active=True,
                metadata={
                    "rationale": "Financial systems have higher business impact from breaches",
                },
            )
        )
        default_scores.append(finance_score)

        # Score 4: User-facing application context
        user_app_score = await self.contextual_score_repo.create_score(
            ContextualScoreCreate(
                name="User-Facing Application Context",
                description="Adjusts severity for user-facing applications",
                context_type=ContextType.USER,
                context_definition={
                    "application_types": ["web", "mobile", "public", "customer"],
                },
                scoring_function={
                    "type": "multiply",
                    "value": 1.3,
                    "conditions": {
                        "vulnerability_type": {
                            "xss": 1.5,
                            "csrf": 1.4,
                            "authentication": 1.6,
                        }
                    },
                },
                is_active=True,
                metadata={
                    "rationale": "User-facing applications have reputation and legal implications",
                },
            )
        )
        default_scores.append(user_app_score)

        return default_scores

    def _apply_adaptive_rule(
        self,
        rule: AdaptiveRule,
        target_id: int,
        job_id: int,
        successful_rules: Optional[List[int]] = None,
        failed_rules: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Apply an adaptive rule to modify decision rules based on feedback.

        Args:
            rule: The adaptive rule to apply
            target_id: The target ID
            job_id: The job ID
            successful_rules: List of rule IDs that were successful
            failed_rules: List of rule IDs that failed

        Returns:
            Dictionary with modifications made
        """
        successful_rules = successful_rules or []
        failed_rules = failed_rules or []

        # Initialize modifications dictionary
        modifications: Dict[str, Any] = {}

        # ... existing code ...

        return modifications
