"""Service layer for the AI Decision Engine."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.ai_decision.models import (
    ConfidenceLevel,
    DecisionRule,
    DecisionRuleCreate,
    DecisionRuleSeverity,
    DecisionRuleType,
    StrategyPhase,
    TestStrategy,
    TestStrategyCreate,
)
from sentinelprobe.ai_decision.repository import (
    DecisionRuleRepository,
    KnowledgeRepository,
    TestStrategyRepository,
)
from sentinelprobe.reconnaissance.models import ServiceType

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
