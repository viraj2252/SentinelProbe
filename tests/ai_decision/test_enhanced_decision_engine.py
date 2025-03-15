"""Tests for the enhanced AI decision engine capabilities."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelprobe.ai_decision.models import (
    AdaptiveRule,
    AdaptiveRuleCreate,
    ConfidenceLevel,
    ContextType,
    ContextualScore,
    ContextualScoreCreate,
    DecisionRule,
    DecisionRuleSeverity,
    DecisionRuleType,
    StrategyPhase,
    TestStrategy,
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
from sentinelprobe.ai_decision.service import DecisionEngineService
from sentinelprobe.reconnaissance.models import Target, TargetStatus
from sentinelprobe.reconnaissance.repository import TargetRepository
from sentinelprobe.vulnerability_scanner.models import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelprobe.vulnerability_scanner.repository import VulnerabilityRepository


@pytest.fixture
def mock_session():
    """Create a mock SQLAlchemy session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.close = AsyncMock()
    session.rollback = AsyncMock()
    return session


@pytest.fixture
def mock_vulnerabilities():
    """Create mock vulnerabilities for testing."""
    return [
        Vulnerability(
            id=1,
            scan_id=1,
            target_id=1,
            name="SQL Injection in login form",
            description="SQL injection vulnerability in the login form",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="Web Application",
            port_number=443,
            protocol="tcp",
            details={
                "url": "/login",
                "parameter": "username",
            },
            remediation="Use prepared statements and input validation",
        ),
        Vulnerability(
            id=2,
            scan_id=1,
            target_id=1,
            name="Weak Authentication Mechanism",
            description="The application uses weak authentication with no MFA",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="Authentication Module",
            port_number=443,
            protocol="tcp",
            details={
                "auth_type": "password-only",
            },
            remediation="Implement multi-factor authentication",
        ),
        Vulnerability(
            id=3,
            scan_id=1,
            target_id=1,
            name="Cross-Site Scripting (XSS)",
            description="Reflected XSS in search functionality",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="Web Application",
            port_number=443,
            protocol="tcp",
            details={
                "url": "/search",
                "parameter": "query",
            },
            remediation="Implement output encoding and content security policy",
        ),
        Vulnerability(
            id=4,
            scan_id=1,
            target_id=1,
            name="MongoDB Authentication Disabled",
            description="MongoDB instance running without authentication",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.UNCONFIRMED,
            affected_component="MongoDB Database",
            port_number=27017,
            protocol="tcp",
            details={
                "auth_status": "disabled",
            },
            remediation="Enable MongoDB authentication",
        ),
    ]


@pytest.fixture
def mock_correlations():
    """Create mock correlation patterns for testing."""
    return [
        VulnerabilityCorrelation(
            id=1,
            name="Web Authentication Attack Chain",
            description="Correlates authentication and web injection vulnerabilities",
            pattern_type="multi_vulnerability",
            pattern_definition={
                "vulnerability_types": ["SQL Injection", "Authentication"],
                "min_severity": "MEDIUM",
            },
            severity_adjustment=1.5,
            confidence=ConfidenceLevel.MEDIUM,
            context_type=ContextType.APPLICATION,
            is_active=True,
            correlation_metadata={},
        ),
        VulnerabilityCorrelation(
            id=2,
            name="Database Security Chain",
            description="Correlates database security vulnerabilities",
            pattern_type="component_chain",
            pattern_definition={
                "components": ["MongoDB", "Database"],
                "min_matches": 1,
            },
            severity_adjustment=1.3,
            confidence=ConfidenceLevel.HIGH,
            context_type=ContextType.DATA,
            is_active=True,
            correlation_metadata={},
        ),
    ]


@pytest.fixture
def mock_context_scores():
    """Create mock contextual scoring rules for testing."""
    return [
        ContextualScore(
            id=1,
            name="Production Environment Score",
            description="Adjusts severity for production environments",
            context_type=ContextType.INFRASTRUCTURE,
            context_definition={
                "environments": ["production", "prod"],
                "criticality": ["high"],
            },
            scoring_function={
                "type": "multiply",
                "value": 1.5,
            },
            is_active=True,
            score_metadata={},
        ),
        ContextualScore(
            id=2,
            name="Database Context Score",
            description="Adjusts severity for database servers",
            context_type=ContextType.DATA,
            context_definition={
                "server_types": ["database", "db", "mongodb"],
            },
            scoring_function={
                "type": "multiply",
                "value": 1.4,
                "conditions": {
                    "vulnerability_type": {
                        "authentication": 1.8,
                    }
                },
            },
            is_active=True,
            score_metadata={},
        ),
    ]


@pytest.fixture
def mock_target():
    """Create a mock target for testing."""
    return Target(
        id=1,
        job_id=1,
        hostname="test-server.example.com",
        ip_address="192.168.1.100",
        status=TargetStatus.COMPLETED,
        target_metadata={
            "environment": "production",
            "criticality": "high",
            "business_unit": "finance",
        },
    )


@pytest.mark.asyncio
class TestEnhancedDecisionEngine:
    """Tests for the enhanced AI decision engine capabilities."""

    async def test_vulnerability_correlation_analysis(
        self, mock_session, mock_vulnerabilities, mock_correlations, mock_target
    ):
        """Test vulnerability correlation analysis functionality."""
        # Setup
        decision_service = DecisionEngineService(mock_session)

        # Mock repositories
        vuln_repo = AsyncMock(spec=VulnerabilityRepository)
        vuln_repo.get_vulnerabilities_by_target.return_value = mock_vulnerabilities
        decision_service.correlation_repo = AsyncMock(
            spec=VulnerabilityCorrelationRepository
        )
        decision_service.correlation_repo.get_active_correlations.return_value = (
            mock_correlations
        )
        decision_service.knowledge_repo = AsyncMock(spec=KnowledgeRepository)
        decision_service.rule_repo = AsyncMock(spec=DecisionRuleRepository)

        # Mock private methods
        decision_service._apply_correlation_pattern = AsyncMock()
        decision_service._apply_correlation_pattern.side_effect = [
            [
                mock_vulnerabilities[0],
                mock_vulnerabilities[1],
            ],  # First pattern matches 2 vulns
            [mock_vulnerabilities[3]],  # Second pattern matches 1 vuln
        ]

        decision_service._calculate_correlated_severity = MagicMock()
        decision_service._calculate_correlated_severity.side_effect = [0.85, 0.9]

        decision_service._create_correlation_rule = AsyncMock()
        decision_service._create_correlation_rule.return_value = MagicMock(id=101)

        # Run the correlation analysis
        with patch(
            "sentinelprobe.vulnerability_scanner.repository.VulnerabilityRepository",
            return_value=vuln_repo,
        ):
            results = await decision_service.analyze_vulnerability_correlations(
                target_id=1
            )

        # Assertions
        assert len(results) == 2, "Should return two correlation results"
        assert (
            decision_service.correlation_repo.get_active_correlations.called
        ), "Should fetch active correlations"
        assert (
            decision_service._apply_correlation_pattern.call_count == 2
        ), "Should apply both correlation patterns"
        assert (
            decision_service._calculate_correlated_severity.call_count == 2
        ), "Should calculate severity for both correlations"
        assert (
            decision_service.knowledge_repo.set_value.call_count == 2
        ), "Should store both correlation results in knowledge base"
        assert (
            decision_service._create_correlation_rule.call_count == 2
        ), "Should create two correlation rules"

        # Verify result structure
        assert "correlation_id" in results[0], "Result should contain correlation ID"
        assert (
            "matched_vulnerabilities" in results[0]
        ), "Result should contain matched vulnerabilities"
        assert (
            "adjusted_severity" in results[0]
        ), "Result should contain adjusted severity"
        assert "confidence" in results[0], "Result should contain confidence level"

    async def test_contextual_scoring(
        self, mock_session, mock_vulnerabilities, mock_context_scores, mock_target
    ):
        """Test contextual scoring functionality."""
        # Setup
        decision_service = DecisionEngineService(mock_session)

        # Mock repositories
        target_repo = AsyncMock(spec=TargetRepository)
        target_repo.get_target.return_value = mock_target

        decision_service.contextual_score_repo = AsyncMock(
            spec=ContextualScoreRepository
        )
        decision_service.contextual_score_repo.get_active_scores.return_value = (
            mock_context_scores
        )

        # Mock private methods for context evaluation
        original_context_applies = decision_service._context_applies_to_target
        original_apply_context = decision_service._apply_context_score

        decision_service._context_applies_to_target = MagicMock()
        decision_service._context_applies_to_target.side_effect = (
            lambda rule, target: True
        )

        decision_service._apply_context_score = MagicMock()
        # Increase score for each vulnerability based on context
        decision_service._apply_context_score.side_effect = [
            0.9,
            0.7,
            0.6,
            0.95,  # Adjusted scores
        ]

        # Run contextual scoring
        with patch(
            "sentinelprobe.reconnaissance.repository.TargetRepository",
            return_value=target_repo,
        ):
            results = await decision_service.apply_contextual_scoring(
                vulnerabilities=mock_vulnerabilities, target_id=1
            )

        # Restore original methods
        decision_service._context_applies_to_target = original_context_applies
        decision_service._apply_context_score = original_apply_context

        # Assertions
        assert len(results) == 4, "Should return four scored vulnerabilities"
        assert target_repo.get_target.called, "Should fetch target information"
        assert (
            decision_service.contextual_score_repo.get_active_scores.called
        ), "Should fetch active contextual scores"
        assert (
            decision_service._context_applies_to_target.call_count == 8
        ), "Should check each context for each vulnerability"
        assert (
            decision_service._apply_context_score.call_count == 4
        ), "Should apply context scoring to each vulnerability"

        # Verify scores were actually adjusted
        assert results[0][1] == 0.9, "First vulnerability should have score of 0.9"
        assert results[3][1] == 0.95, "Fourth vulnerability should have score of 0.95"

        # Check that the vulnerabilities are correctly associated with their scores
        assert results[0][0].id == 1, "First vulnerability should be SQL Injection"
        assert (
            results[3][0].id == 4
        ), "Fourth vulnerability should be MongoDB Authentication"

    async def test_adaptive_rule_learning(self, mock_session):
        """Test adaptive rule learning and evolution functionality."""
        # Setup
        decision_service = DecisionEngineService(mock_session)

        # Mock repositories
        adaptive_rule_repo = AsyncMock(spec=AdaptiveRuleRepository)
        decision_service.adaptive_rule_repo = adaptive_rule_repo
        target_repo = AsyncMock(spec=TargetRepository)
        target_repo.get_target.return_value = MagicMock(
            id=1, target_metadata={"criticality": "high"}
        )

        # Mock methods for rule adaptation
        failed_rule = MagicMock(spec=AdaptiveRule)
        failed_rule.id = 101
        failed_rule.effectiveness_score = 0.3
        failed_rule.failure_count = 3
        failed_rule.rule_type = DecisionRuleType.VULNERABILITY_SCAN
        failed_rule.conditions = {"service_type": "http"}

        successful_rule = MagicMock(spec=AdaptiveRule)
        successful_rule.id = 102
        successful_rule.effectiveness_score = 0.8

        decision_service.adaptive_rule_repo.get_adaptive_rule.side_effect = (
            lambda rule_id: {101: failed_rule, 102: successful_rule}.get(rule_id)
        )

        decision_service.adaptive_rule_repo.update_rule_effectiveness.side_effect = [
            successful_rule,
            failed_rule,
        ]

        # Mock rule evolution
        decision_service._evolve_ineffective_rule = AsyncMock()
        decision_service._evolve_ineffective_rule.return_value = MagicMock(id=201)

        # Mock strategy retrieval
        decision_service.strategy_repo = AsyncMock(spec=TestStrategyRepository)
        strategy = MagicMock(spec=TestStrategy)
        rule = MagicMock(spec=DecisionRule)
        rule.id = 301
        rule.severity = DecisionRuleSeverity.HIGH
        strategy.rules = [rule]
        decision_service.strategy_repo.get_strategies_by_job.return_value = [strategy]

        # Mock adaptive rule conversion
        decision_service._convert_to_adaptive_rule = AsyncMock()
        decision_service._convert_to_adaptive_rule.return_value = MagicMock(id=401)

        # Mock existing adaptive rule check
        decision_service.adaptive_rule_repo.get_adaptive_rules_by_base_rule.return_value = (
            []
        )

        # Run adaptive rule evaluation
        with patch(
            "sentinelprobe.reconnaissance.repository.TargetRepository",
            return_value=target_repo,
        ):
            results = await decision_service.evaluate_and_adapt_rules(
                job_id=1, target_id=1, successful_rules=[102], failed_rules=[101]
            )

        # Assertions
        assert len(results) == 3, "Should return three adaptation results"
        assert (
            decision_service.adaptive_rule_repo.update_rule_effectiveness.call_count
            == 2
        ), "Should update effectiveness for two rules"
        assert (
            decision_service._evolve_ineffective_rule.call_count == 1
        ), "Should evolve one ineffective rule"
        assert (
            decision_service.adaptive_rule_repo.get_adaptive_rules_by_base_rule.call_count
            == 1
        ), "Should check for existing adaptive rules"
        assert (
            decision_service._convert_to_adaptive_rule.call_count == 1
        ), "Should convert one standard rule to adaptive"

        # Verify results contain expected actions
        actions = [r["action"] for r in results]
        assert "updated" in actions, "Result should contain 'updated' action"
        assert "evolved" in actions, "Result should contain 'evolved' action"
        assert "converted" in actions, "Result should contain 'converted' action"

    async def test_enhanced_vulnerability_prioritization(
        self,
        mock_session,
        mock_vulnerabilities,
        mock_correlations,
        mock_context_scores,
        mock_target,
    ):
        """Test enhanced vulnerability prioritization with correlation and context."""
        # Setup
        decision_service = DecisionEngineService(mock_session)

        # Mock repositories
        vuln_repo = AsyncMock(spec=VulnerabilityRepository)
        vuln_repo.get_vulnerabilities_by_target.return_value = mock_vulnerabilities

        target_repo = AsyncMock(spec=TargetRepository)
        target_repo.get_target.return_value = mock_target

        decision_service.contextual_score_repo = AsyncMock(
            spec=ContextualScoreRepository
        )
        decision_service.contextual_score_repo.get_active_scores.return_value = (
            mock_context_scores
        )

        decision_service.correlation_repo = AsyncMock(
            spec=VulnerabilityCorrelationRepository
        )
        decision_service.correlation_repo.get_active_correlations.return_value = (
            mock_correlations
        )

        decision_service.strategy_repo = AsyncMock(spec=TestStrategyRepository)
        decision_service.strategy_repo.create_strategy.return_value = MagicMock(id=501)

        # Mock methods
        decision_service.apply_contextual_scoring = AsyncMock()
        decision_service.apply_contextual_scoring.return_value = [
            (mock_vulnerabilities[0], 0.85),  # SQL Injection
            (mock_vulnerabilities[1], 0.65),  # Weak Auth
            (mock_vulnerabilities[2], 0.55),  # XSS
            (mock_vulnerabilities[3], 0.95),  # MongoDB Auth
        ]

        decision_service.analyze_vulnerability_correlations = AsyncMock()
        decision_service.analyze_vulnerability_correlations.return_value = [
            {
                "correlation_id": 1,
                "correlation_name": "Web Authentication Attack Chain",
                "matched_vulnerabilities": [1, 2],  # IDs of vulnerabilities
                "adjusted_severity": 0.9,
                "context_type": "application",
                "confidence": "medium",
            }
        ]

        decision_service.create_vulnerability_based_rules = AsyncMock()

        # Run enhanced prioritization
        with patch(
            "sentinelprobe.vulnerability_scanner.repository.VulnerabilityRepository",
            return_value=vuln_repo,
        ):
            strategy = await decision_service.enhance_vulnerability_prioritization(
                target_id=1, job_id=1
            )

        # Assertions
        assert strategy is not None, "Should return a strategy"
        assert (
            decision_service.apply_contextual_scoring.called
        ), "Should apply contextual scoring"
        assert (
            decision_service.analyze_vulnerability_correlations.called
        ), "Should analyze vulnerability correlations"
        assert (
            decision_service.strategy_repo.create_strategy.called
        ), "Should create a strategy"
        assert (
            decision_service.create_vulnerability_based_rules.called
        ), "Should create vulnerability rules"

        # Verify strategy parameters were created with correlation info
        strategy_params = decision_service.strategy_repo.create_strategy.call_args[0][
            0
        ].parameters
        assert (
            "correlation_count" in strategy_params
        ), "Strategy should include correlation count"
        assert (
            "applied_correlations" in strategy_params
        ), "Strategy should include applied correlations"
        assert (
            strategy_params["strategy_approach"] == "enhanced_prioritization"
        ), "Strategy should use enhanced approach"
