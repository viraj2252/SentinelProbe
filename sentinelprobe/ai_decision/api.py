"""API routes for the AI Decision Engine module."""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.ai_decision.models import (
    DecisionRuleCreate,
    DecisionRuleResponse,
    DecisionRuleUpdate,
    KnowledgeItem,
    KnowledgeItemCreate,
    KnowledgeItemResponse,
    KnowledgeItemUpdate,
    TestStrategyCreate,
    TestStrategyResponse,
    TestStrategyUpdate,
)
from sentinelprobe.ai_decision.service import DecisionEngineService
from sentinelprobe.core.db import get_db_session
from sentinelprobe.vulnerability_scanner.models import VulnerabilityResponse
from sentinelprobe.vulnerability_scanner.service import VulnerabilityScannerService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-decision", tags=["ai-decision"])


@router.post("/knowledge", response_model=KnowledgeItemResponse)
async def create_knowledge_item(
    knowledge_item: KnowledgeItemCreate,
    session: AsyncSession = Depends(get_db_session),
) -> KnowledgeItemResponse:
    """Create a new knowledge item.

    Args:
        knowledge_item: Knowledge item creation data
        session: Database session

    Returns:
        Created knowledge item
    """
    service = DecisionEngineService(session)
    knowledge_repo = service.knowledge_repo
    created_item: KnowledgeItem = await knowledge_repo.create_knowledge_item(
        knowledge_item
    )
    result: KnowledgeItemResponse = KnowledgeItemResponse.model_validate(
        created_item.__dict__
    )
    return result


@router.get("/knowledge/{item_id}", response_model=KnowledgeItemResponse)
async def get_knowledge_item(
    item_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> KnowledgeItemResponse:
    """Get a knowledge item by ID.

    Args:
        item_id: Knowledge item ID
        session: Database session

    Returns:
        Knowledge item
    """
    service = DecisionEngineService(session)
    knowledge_repo = service.knowledge_repo
    item = await knowledge_repo.get_knowledge_item(item_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge item with ID {item_id} not found",
        )
    result: KnowledgeItemResponse = KnowledgeItemResponse.model_validate(item.__dict__)
    return result


@router.put("/knowledge/{item_id}", response_model=KnowledgeItemResponse)
async def update_knowledge_item(
    item_id: int,
    update_data: KnowledgeItemUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> KnowledgeItemResponse:
    """Update a knowledge item.

    Args:
        item_id: Knowledge item ID
        update_data: Knowledge item update data
        session: Database session

    Returns:
        Updated knowledge item
    """
    service = DecisionEngineService(session)
    knowledge_repo = service.knowledge_repo
    updated_item = await knowledge_repo.update_knowledge_item(item_id, update_data)
    if not updated_item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge item with ID {item_id} not found",
        )
    result: KnowledgeItemResponse = KnowledgeItemResponse.model_validate(
        updated_item.__dict__
    )
    return result


@router.get("/knowledge/target/{target_id}", response_model=List[KnowledgeItemResponse])
async def get_target_knowledge(
    target_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[KnowledgeItemResponse]:
    """Get all knowledge items for a target.

    Args:
        target_id: Target ID
        session: Database session

    Returns:
        List of knowledge items
    """
    service = DecisionEngineService(session)
    knowledge_repo = service.knowledge_repo
    items = await knowledge_repo.get_knowledge_items_by_target(target_id)
    result: List[KnowledgeItemResponse] = [
        KnowledgeItemResponse.model_validate(item.__dict__) for item in items
    ]
    return result


@router.post("/rules", response_model=DecisionRuleResponse)
async def create_decision_rule(
    rule: DecisionRuleCreate,
    session: AsyncSession = Depends(get_db_session),
) -> DecisionRuleResponse:
    """Create a new decision rule.

    Args:
        rule: Decision rule creation data
        session: Database session

    Returns:
        Created decision rule
    """
    service = DecisionEngineService(session)
    rule_repo = service.rule_repo
    created_rule = await rule_repo.create_rule(rule)
    result: DecisionRuleResponse = DecisionRuleResponse.model_validate(
        created_rule.__dict__
    )
    return result


@router.get("/rules/{rule_id}", response_model=DecisionRuleResponse)
async def get_decision_rule(
    rule_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> DecisionRuleResponse:
    """Get a decision rule by ID.

    Args:
        rule_id: Decision rule ID
        session: Database session

    Returns:
        Decision rule
    """
    service = DecisionEngineService(session)
    rule_repo = service.rule_repo
    rule = await rule_repo.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision rule with ID {rule_id} not found",
        )
    result: DecisionRuleResponse = DecisionRuleResponse.model_validate(rule.__dict__)
    return result


@router.put("/rules/{rule_id}", response_model=DecisionRuleResponse)
async def update_decision_rule(
    rule_id: int,
    update_data: DecisionRuleUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> DecisionRuleResponse:
    """Update a decision rule.

    Args:
        rule_id: Decision rule ID
        update_data: Decision rule update data
        session: Database session

    Returns:
        Updated decision rule
    """
    service = DecisionEngineService(session)
    rule_repo = service.rule_repo
    updated_rule = await rule_repo.update_rule(rule_id, update_data)
    if not updated_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision rule with ID {rule_id} not found",
        )
    result: DecisionRuleResponse = DecisionRuleResponse.model_validate(
        updated_rule.__dict__
    )
    return result


@router.get("/rules/type/{rule_type}", response_model=List[DecisionRuleResponse])
async def get_rules_by_type(
    rule_type: str,
    session: AsyncSession = Depends(get_db_session),
) -> List[DecisionRuleResponse]:
    """Get decision rules by type.

    Args:
        rule_type: Decision rule type
        session: Database session

    Returns:
        List of decision rules
    """
    service = DecisionEngineService(session)
    rule_repo = service.rule_repo
    rules = await rule_repo.get_rules_by_type(rule_type)
    result: List[DecisionRuleResponse] = [
        DecisionRuleResponse.model_validate(rule.__dict__) for rule in rules
    ]
    return result


@router.post("/strategies", response_model=TestStrategyResponse)
async def create_test_strategy(
    strategy: TestStrategyCreate,
    session: AsyncSession = Depends(get_db_session),
) -> TestStrategyResponse:
    """Create a new test strategy.

    Args:
        strategy: Test strategy creation data
        session: Database session

    Returns:
        Created test strategy
    """
    service = DecisionEngineService(session)
    strategy_repo = service.strategy_repo
    created_strategy = await strategy_repo.create_strategy(strategy)
    result: TestStrategyResponse = TestStrategyResponse.model_validate(
        created_strategy.__dict__
    )
    return result


@router.get("/strategies/{strategy_id}", response_model=TestStrategyResponse)
async def get_test_strategy(
    strategy_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> TestStrategyResponse:
    """Get a test strategy by ID.

    Args:
        strategy_id: Test strategy ID
        session: Database session

    Returns:
        Test strategy
    """
    service = DecisionEngineService(session)
    strategy_repo = service.strategy_repo
    strategy = await strategy_repo.get_strategy(strategy_id)
    if not strategy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test strategy with ID {strategy_id} not found",
        )
    result: TestStrategyResponse = TestStrategyResponse.model_validate(
        strategy.__dict__
    )
    return result


@router.put("/strategies/{strategy_id}", response_model=TestStrategyResponse)
async def update_test_strategy(
    strategy_id: int,
    update_data: TestStrategyUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> TestStrategyResponse:
    """Update a test strategy.

    Args:
        strategy_id: Test strategy ID
        update_data: Test strategy update data
        session: Database session

    Returns:
        Updated test strategy
    """
    service = DecisionEngineService(session)
    strategy_repo = service.strategy_repo
    updated_strategy = await strategy_repo.update_strategy(strategy_id, update_data)
    if not updated_strategy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test strategy with ID {strategy_id} not found",
        )
    result: TestStrategyResponse = TestStrategyResponse.model_validate(
        updated_strategy.__dict__
    )
    return result


@router.get("/job/{job_id}/strategies", response_model=List[TestStrategyResponse])
async def get_job_strategies(
    job_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[TestStrategyResponse]:
    """Get all test strategies for a job.

    Args:
        job_id: Job ID
        session: Database session

    Returns:
        List of test strategies
    """
    service = DecisionEngineService(session)
    strategy_repo = service.strategy_repo
    strategies = await strategy_repo.get_strategies_by_job(job_id)
    result: List[TestStrategyResponse] = [
        TestStrategyResponse.model_validate(strategy.__dict__)
        for strategy in strategies
    ]
    return result


@router.post("/formulate-strategy/{job_id}", response_model=List[TestStrategyResponse])
async def formulate_job_strategy(
    job_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[TestStrategyResponse]:
    """Formulate a test strategy for a job.

    Args:
        job_id: Job ID
        session: Database session

    Returns:
        Created test strategies
    """
    service = DecisionEngineService(session)
    strategies = await service.formulate_strategy(job_id)
    result: List[TestStrategyResponse] = [
        TestStrategyResponse.model_validate(strategy.__dict__)
        for strategy in strategies
    ]
    return result


@router.post("/init-default-rules", response_model=List[DecisionRuleResponse])
async def initialize_default_rules(
    session: AsyncSession = Depends(get_db_session),
) -> List[DecisionRuleResponse]:
    """Initialize default decision rules.

    Args:
        session: Database session

    Returns:
        Created default rules
    """
    service = DecisionEngineService(session)
    rules = await service.initialize_default_rules()
    result: List[DecisionRuleResponse] = [
        DecisionRuleResponse.model_validate(rule.__dict__) for rule in rules
    ]
    return result


@router.post(
    "/vulnerability-prioritization/target/{target_id}/job/{job_id}",
    response_model=TestStrategyResponse,
)
async def create_prioritized_vulnerability_strategy(
    target_id: int,
    job_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> TestStrategyResponse:
    """Create a test strategy based on vulnerability prioritization.

    Args:
        target_id: Target ID
        job_id: Job ID
        session: Database session

    Returns:
        Created test strategy
    """
    service = DecisionEngineService(session)
    strategy = await service.analyze_vulnerability_prioritization(target_id, job_id)
    if not strategy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No vulnerabilities found for target {target_id}",
        )
    result: TestStrategyResponse = TestStrategyResponse.model_validate(
        strategy.__dict__
    )
    return result


@router.get(
    "/vulnerability-prioritization/target/{target_id}", response_model=List[Dict]
)
async def get_prioritized_vulnerabilities(
    target_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """Get prioritized vulnerabilities for a target.

    Args:
        target_id: Target ID
        session: Database session

    Returns:
        List of prioritized vulnerabilities with scores
    """
    vuln_service = VulnerabilityScannerService(session)
    prioritized_vulns = await vuln_service.prioritize_target_vulnerabilities(
        target_id=target_id, include_business_impact=True
    )

    if not prioritized_vulns:
        return []

    # Format response
    result = []
    for vuln, score in prioritized_vulns:
        result.append(
            {
                "vulnerability": VulnerabilityResponse.model_validate(vuln.__dict__),
                "priority_score": score,
                "priority_factors": {
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "has_cve": bool(vuln.cve_id),
                    "exploitability": (
                        vuln.details.get("exploitability") if vuln.details else None
                    ),
                    "business_impact": (
                        vuln.details.get("business_impact") if vuln.details else None
                    ),
                },
            }
        )

    return result


@router.post("/vulnerability-prioritization/scan/{scan_id}", response_model=List[Dict])
async def prioritize_scan_vulnerabilities(
    scan_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """Prioritize vulnerabilities from a specific scan.

    Args:
        scan_id: Scan ID
        session: Database session

    Returns:
        List of prioritized vulnerabilities with scores
    """
    vuln_service = VulnerabilityScannerService(session)

    # Check if scan exists
    scan = await vuln_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found",
        )

    # Get prioritized vulnerabilities
    prioritized_vulns = await vuln_service.prioritize_scan_vulnerabilities(
        scan_id=scan_id, include_business_impact=True
    )

    if not prioritized_vulns:
        return []

    # Format response
    result = []
    for vuln, score in prioritized_vulns:
        result.append(
            {
                "vulnerability": VulnerabilityResponse.model_validate(vuln.__dict__),
                "priority_score": score,
                "priority_factors": {
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "has_cve": bool(vuln.cve_id),
                    "exploitability": (
                        vuln.details.get("exploitability") if vuln.details else None
                    ),
                    "business_impact": (
                        vuln.details.get("business_impact") if vuln.details else None
                    ),
                },
            }
        )

    return result


@router.post(
    "/test-path-optimization/target/{target_id}/job/{job_id}",
    response_model=List[DecisionRuleResponse],
)
async def create_optimized_test_path_rules(
    target_id: int,
    job_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> List[DecisionRuleResponse]:
    """Create optimized test path rules based on vulnerability prioritization.

    Args:
        target_id: Target ID
        job_id: Job ID
        session: Database session

    Returns:
        Created decision rules
    """
    # First get the service instances
    decision_service = DecisionEngineService(session)
    vuln_service = VulnerabilityScannerService(session)

    # Get prioritized vulnerabilities
    prioritized_vulns = await vuln_service.prioritize_target_vulnerabilities(
        target_id=target_id, include_business_impact=True
    )

    if not prioritized_vulns:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No vulnerabilities found for target {target_id}",
        )

    # Create decision rules from prioritized vulnerabilities
    rules = await decision_service.create_vulnerability_based_rules(prioritized_vulns)

    # Create test strategy
    await decision_service.analyze_vulnerability_prioritization(target_id, job_id)

    result: List[DecisionRuleResponse] = [
        DecisionRuleResponse.model_validate(rule.__dict__) for rule in rules
    ]
    return result
