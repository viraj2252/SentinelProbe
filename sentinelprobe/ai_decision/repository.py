"""Repository classes for the AI Decision Engine."""

from datetime import datetime
from typing import Any, Dict, List, Optional, cast

from sqlalchemy import select
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
    DecisionRuleUpdate,
    KnowledgeItem,
    KnowledgeItemCreate,
    KnowledgeItemUpdate,
    TestStrategy,
    TestStrategyCreate,
    TestStrategyUpdate,
    VulnerabilityCorrelation,
    VulnerabilityCorrelationCreate,
)


class KnowledgeRepository:
    """Repository for the Knowledge items."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_knowledge_item(
        self, item_data: KnowledgeItemCreate
    ) -> KnowledgeItem:
        """Create a new knowledge item.

        Args:
            item_data: Knowledge item data

        Returns:
            Created knowledge item
        """
        item = KnowledgeItem(
            target_id=item_data.target_id,
            key=item_data.key,
            value_type=item_data.value_type,
            string_value=item_data.string_value,
            int_value=item_data.int_value,
            float_value=item_data.float_value,
            bool_value=item_data.bool_value,
            json_value=item_data.json_value,
            confidence=item_data.confidence,
            item_metadata=item_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(item)
        await self.session.flush()
        await self.session.refresh(item)
        return item

    async def get_knowledge_item(self, item_id: int) -> Optional[KnowledgeItem]:
        """Get a knowledge item by ID.

        Args:
            item_id: Knowledge item ID

        Returns:
            Knowledge item or None if not found
        """
        result = await self.session.execute(
            select(KnowledgeItem).where(KnowledgeItem.id == item_id)
        )
        item: Optional[KnowledgeItem] = result.scalars().first()
        return item

    async def get_knowledge_item_by_key(
        self, key: str, target_id: Optional[int] = None
    ) -> Optional[KnowledgeItem]:
        """Get a knowledge item by key and optional target ID.

        Args:
            key: Knowledge item key
            target_id: Optional target ID

        Returns:
            Knowledge item or None if not found
        """
        query = select(KnowledgeItem).where(KnowledgeItem.key == key)
        if target_id is not None:
            query = query.where(KnowledgeItem.target_id == target_id)
        result = await self.session.execute(query)
        item: Optional[KnowledgeItem] = result.scalars().first()
        return item

    async def get_knowledge_items_by_target(
        self, target_id: int
    ) -> List[KnowledgeItem]:
        """Get all knowledge items for a target.

        Args:
            target_id: Target ID

        Returns:
            List of knowledge items
        """
        result = await self.session.execute(
            select(KnowledgeItem).where(KnowledgeItem.target_id == target_id)
        )
        return list(result.scalars().all())

    async def get_knowledge_items_by_key_prefix(
        self, key_prefix: str, target_id: Optional[int] = None
    ) -> List[KnowledgeItem]:
        """Get knowledge items by key prefix.

        Args:
            key_prefix: Knowledge item key prefix
            target_id: Optional target ID

        Returns:
            List of knowledge items
        """
        query = select(KnowledgeItem).where(KnowledgeItem.key.startswith(key_prefix))
        if target_id is not None:
            query = query.where(KnowledgeItem.target_id == target_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_knowledge_item(
        self, item_id: int, item_data: KnowledgeItemUpdate
    ) -> Optional[KnowledgeItem]:
        """Update a knowledge item.

        Args:
            item_id: Knowledge item ID
            item_data: Knowledge item update data

        Returns:
            Updated knowledge item or None if not found
        """
        db_item = await self.get_knowledge_item(item_id)
        if not db_item:
            return None

        # Update fields if provided
        update_data = item_data.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_item, key, value)

        db_item.updated_at = datetime.utcnow()
        self.session.add(db_item)
        await self.session.flush()
        await self.session.refresh(db_item)
        return db_item

    async def delete_knowledge_item(self, item_id: int) -> bool:
        """Delete a knowledge item.

        Args:
            item_id: Knowledge item ID

        Returns:
            True if deleted, False if not found
        """
        db_item = await self.get_knowledge_item(item_id)
        if not db_item:
            return False

        await self.session.delete(db_item)
        await self.session.flush()
        return True

    async def get_value(
        self, key: str, target_id: Optional[int] = None
    ) -> Optional[Any]:
        """Get a knowledge item value by key.

        Args:
            key: Knowledge item key
            target_id: Optional target ID

        Returns:
            Knowledge item value or None if not found
        """
        item = await self.get_knowledge_item_by_key(key, target_id)
        if not item:
            return None

        # Return appropriate value based on value type
        if item.value_type == "string":
            return item.string_value
        elif item.value_type == "int":
            return item.int_value
        elif item.value_type == "float":
            return item.float_value
        elif item.value_type == "bool":
            return item.bool_value
        elif item.value_type == "json":
            return item.json_value
        else:
            return None

    async def set_value(
        self,
        key: str,
        value: Any,
        target_id: Optional[int] = None,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[KnowledgeItem]:
        """Set a knowledge item value.

        Args:
            key: Knowledge item key
            value: Knowledge item value
            target_id: Optional target ID
            confidence: Confidence level
            metadata: Optional metadata

        Returns:
            Created or updated knowledge item
        """
        # Determine value type and set appropriate field
        if isinstance(value, str):
            value_type = "string"
            item_data = KnowledgeItemCreate(
                target_id=target_id,
                key=key,
                value_type=value_type,
                string_value=value,
                confidence=confidence,
                metadata=metadata or {},
            )
        elif isinstance(value, int):
            value_type = "int"
            item_data = KnowledgeItemCreate(
                target_id=target_id,
                key=key,
                value_type=value_type,
                int_value=value,
                confidence=confidence,
                metadata=metadata or {},
            )
        elif isinstance(value, float):
            value_type = "float"
            item_data = KnowledgeItemCreate(
                target_id=target_id,
                key=key,
                value_type=value_type,
                float_value=value,
                confidence=confidence,
                metadata=metadata or {},
            )
        elif isinstance(value, bool):
            value_type = "bool"
            item_data = KnowledgeItemCreate(
                target_id=target_id,
                key=key,
                value_type=value_type,
                bool_value=value,
                confidence=confidence,
                metadata=metadata or {},
            )
        elif isinstance(value, (dict, list)):
            value_type = "json"
            item_data = KnowledgeItemCreate(
                target_id=target_id,
                key=key,
                value_type=value_type,
                json_value=cast(Dict[str, Any], value),
                confidence=confidence,
                metadata=metadata or {},
            )
        else:
            raise ValueError(f"Unsupported value type: {type(value)}")

        # Check if item already exists
        existing_item = await self.get_knowledge_item_by_key(key, target_id)
        if existing_item:
            # Update existing item
            update_data = KnowledgeItemUpdate(
                value_type=value_type,
                string_value=item_data.string_value,
                int_value=item_data.int_value,
                float_value=item_data.float_value,
                bool_value=item_data.bool_value,
                json_value=item_data.json_value,
                confidence=confidence,
            )
            if metadata:
                update_data.metadata = {**existing_item.item_metadata, **metadata}

            return await self.update_knowledge_item(existing_item.id, update_data)
        else:
            # Create new item
            return await self.create_knowledge_item(item_data)


class DecisionRuleRepository:
    """Repository for decision rules."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_rule(self, rule_data: DecisionRuleCreate) -> DecisionRule:
        """Create a new decision rule.

        Args:
            rule_data: Decision rule data

        Returns:
            Created decision rule
        """
        rule = DecisionRule(
            name=rule_data.name,
            description=rule_data.description,
            rule_type=rule_data.rule_type,
            severity=rule_data.severity,
            conditions=rule_data.conditions,
            actions=rule_data.actions,
            is_active=rule_data.is_active,
            priority=rule_data.priority,
            rule_metadata=rule_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(rule)
        await self.session.flush()
        await self.session.refresh(rule)
        return rule

    async def get_rule(self, rule_id: int) -> Optional[DecisionRule]:
        """Get a decision rule by ID.

        Args:
            rule_id: Decision rule ID

        Returns:
            Decision rule or None if not found
        """
        result = await self.session.execute(
            select(DecisionRule).where(DecisionRule.id == rule_id)
        )
        rule: Optional[DecisionRule] = result.scalars().first()
        return rule

    async def get_rules_by_type(
        self, rule_type: str, active_only: bool = True
    ) -> List[DecisionRule]:
        """Get decision rules by type.

        Args:
            rule_type: Decision rule type
            active_only: Whether to return only active rules

        Returns:
            List of decision rules
        """
        query = select(DecisionRule).where(DecisionRule.rule_type == rule_type)
        if active_only:
            query = query.where(DecisionRule.is_active)
        # Order by priority (lower numbers first)
        query = query.order_by(DecisionRule.priority)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_rule(
        self, rule_id: int, rule_data: DecisionRuleUpdate
    ) -> Optional[DecisionRule]:
        """Update a decision rule.

        Args:
            rule_id: Decision rule ID
            rule_data: Decision rule update data

        Returns:
            Updated decision rule or None if not found
        """
        db_rule = await self.get_rule(rule_id)
        if not db_rule:
            return None

        # Update fields if provided
        update_data = rule_data.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_rule, key, value)

        db_rule.updated_at = datetime.utcnow()
        self.session.add(db_rule)
        await self.session.flush()
        await self.session.refresh(db_rule)
        return db_rule

    async def delete_rule(self, rule_id: int) -> bool:
        """Delete a decision rule.

        Args:
            rule_id: Decision rule ID

        Returns:
            True if deleted, False if not found
        """
        db_rule = await self.get_rule(rule_id)
        if not db_rule:
            return False

        await self.session.delete(db_rule)
        await self.session.flush()
        return True


class TestStrategyRepository:
    """Repository for test strategies."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_strategy(self, strategy_data: TestStrategyCreate) -> TestStrategy:
        """Create a new test strategy.

        Args:
            strategy_data: Test strategy data

        Returns:
            Created test strategy
        """
        strategy = TestStrategy(
            job_id=strategy_data.job_id,
            name=strategy_data.name,
            description=strategy_data.description,
            phase=strategy_data.phase,
            parameters=strategy_data.parameters,
            is_active=strategy_data.is_active,
            priority=strategy_data.priority,
            strategy_metadata=strategy_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(strategy)
        await self.session.flush()
        await self.session.refresh(strategy)
        return strategy

    async def get_strategy(self, strategy_id: int) -> Optional[TestStrategy]:
        """Get a test strategy by ID.

        Args:
            strategy_id: Test strategy ID

        Returns:
            Test strategy or None if not found
        """
        result = await self.session.execute(
            select(TestStrategy).where(TestStrategy.id == strategy_id)
        )
        strategy: Optional[TestStrategy] = result.scalars().first()
        return strategy

    async def get_strategies_by_job(
        self, job_id: int, active_only: bool = True
    ) -> List[TestStrategy]:
        """Get test strategies by job ID.

        Args:
            job_id: Job ID
            active_only: Whether to return only active strategies

        Returns:
            List of test strategies
        """
        query = select(TestStrategy).where(TestStrategy.job_id == job_id)
        if active_only:
            query = query.where(TestStrategy.is_active)
        # Order by priority (lower numbers first)
        query = query.order_by(TestStrategy.priority)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_strategies_by_phase(
        self, job_id: int, phase: str, active_only: bool = True
    ) -> List[TestStrategy]:
        """Get test strategies by phase.

        Args:
            job_id: Job ID
            phase: Strategy phase
            active_only: Whether to return only active strategies

        Returns:
            List of test strategies
        """
        query = select(TestStrategy).where(
            TestStrategy.job_id == job_id, TestStrategy.phase == phase
        )
        if active_only:
            query = query.where(TestStrategy.is_active)
        # Order by priority (lower numbers first)
        query = query.order_by(TestStrategy.priority)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_strategy(
        self, strategy_id: int, strategy_data: TestStrategyUpdate
    ) -> Optional[TestStrategy]:
        """Update a test strategy.

        Args:
            strategy_id: Test strategy ID
            strategy_data: Test strategy update data

        Returns:
            Updated test strategy or None if not found
        """
        db_strategy = await self.get_strategy(strategy_id)
        if not db_strategy:
            return None

        # Update fields if provided
        update_data = strategy_data.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_strategy, key, value)

        db_strategy.updated_at = datetime.utcnow()
        self.session.add(db_strategy)
        await self.session.flush()
        await self.session.refresh(db_strategy)
        return db_strategy

    async def delete_strategy(self, strategy_id: int) -> bool:
        """Delete a test strategy.

        Args:
            strategy_id: Test strategy ID

        Returns:
            True if deleted, False if not found
        """
        db_strategy = await self.get_strategy(strategy_id)
        if not db_strategy:
            return False

        await self.session.delete(db_strategy)
        await self.session.flush()
        return True

    async def add_rule_to_strategy(
        self, strategy_id: int, rule_id: int
    ) -> Optional[TestStrategy]:
        """Add a rule to a strategy.

        Args:
            strategy_id: Test strategy ID
            rule_id: Decision rule ID

        Returns:
            Updated test strategy or None if not found
        """
        db_strategy = await self.get_strategy(strategy_id)
        if not db_strategy:
            return None

        # Get the rule
        rule_repo = DecisionRuleRepository(self.session)
        db_rule = await rule_repo.get_rule(rule_id)
        if not db_rule:
            return None

        # Add rule to strategy
        db_strategy.rules.append(db_rule)
        self.session.add(db_strategy)
        await self.session.flush()
        await self.session.refresh(db_strategy)
        return db_strategy

    async def remove_rule_from_strategy(
        self, strategy_id: int, rule_id: int
    ) -> Optional[TestStrategy]:
        """Remove a rule from a strategy.

        Args:
            strategy_id: Test strategy ID
            rule_id: Decision rule ID

        Returns:
            Updated test strategy or None if not found
        """
        db_strategy = await self.get_strategy(strategy_id)
        if not db_strategy:
            return None

        # Get the rule
        rule_repo = DecisionRuleRepository(self.session)
        db_rule = await rule_repo.get_rule(rule_id)
        if not db_rule:
            return None

        # Remove rule from strategy
        db_strategy.rules.remove(db_rule)
        self.session.add(db_strategy)
        await self.session.flush()
        await self.session.refresh(db_strategy)
        return db_strategy


class VulnerabilityCorrelationRepository:
    """Repository for vulnerability correlation patterns."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_correlation(
        self, correlation_data: VulnerabilityCorrelationCreate
    ) -> VulnerabilityCorrelation:
        """Create a new vulnerability correlation pattern.

        Args:
            correlation_data: Vulnerability correlation data

        Returns:
            Created vulnerability correlation
        """
        correlation = VulnerabilityCorrelation(
            name=correlation_data.name,
            description=correlation_data.description,
            pattern_type=correlation_data.pattern_type,
            pattern_definition=correlation_data.pattern_definition,
            severity_adjustment=correlation_data.severity_adjustment,
            confidence=correlation_data.confidence,
            context_type=correlation_data.context_type,
            is_active=correlation_data.is_active,
            correlation_metadata=correlation_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(correlation)
        await self.session.flush()
        await self.session.refresh(correlation)
        return correlation

    async def get_correlation(
        self, correlation_id: int
    ) -> Optional[VulnerabilityCorrelation]:
        """Get a vulnerability correlation by ID.

        Args:
            correlation_id: Vulnerability correlation ID

        Returns:
            Vulnerability correlation or None if not found
        """
        result = await self.session.execute(
            select(VulnerabilityCorrelation).where(
                VulnerabilityCorrelation.id == correlation_id
            )
        )
        correlation: Optional[VulnerabilityCorrelation] = result.scalars().first()
        return correlation

    async def get_correlations_by_context_type(
        self, context_type: ContextType, active_only: bool = True
    ) -> List[VulnerabilityCorrelation]:
        """Get vulnerability correlations by context type.

        Args:
            context_type: Context type
            active_only: Whether to return only active correlations

        Returns:
            List of vulnerability correlations
        """
        query = select(VulnerabilityCorrelation).where(
            VulnerabilityCorrelation.context_type == context_type
        )
        if active_only:
            query = query.where(VulnerabilityCorrelation.is_active)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_correlations(self) -> List[VulnerabilityCorrelation]:
        """Get all active vulnerability correlations.

        Returns:
            List of active vulnerability correlations
        """
        result = await self.session.execute(
            select(VulnerabilityCorrelation).where(VulnerabilityCorrelation.is_active)
        )
        return list(result.scalars().all())

    async def update_correlation(
        self, correlation_id: int, correlation_data: dict
    ) -> Optional[VulnerabilityCorrelation]:
        """Update a vulnerability correlation.

        Args:
            correlation_id: Vulnerability correlation ID
            correlation_data: Vulnerability correlation update data

        Returns:
            Updated vulnerability correlation or None if not found
        """
        db_correlation = await self.get_correlation(correlation_id)
        if not db_correlation:
            return None

        # Update fields if provided
        for key, value in correlation_data.items():
            if hasattr(db_correlation, key):
                setattr(db_correlation, key, value)

        db_correlation.updated_at = datetime.utcnow()
        self.session.add(db_correlation)
        await self.session.flush()
        await self.session.refresh(db_correlation)
        return db_correlation

    async def delete_correlation(self, correlation_id: int) -> bool:
        """Delete a vulnerability correlation.

        Args:
            correlation_id: Vulnerability correlation ID

        Returns:
            True if deleted, False if not found
        """
        db_correlation = await self.get_correlation(correlation_id)
        if not db_correlation:
            return False

        await self.session.delete(db_correlation)
        await self.session.flush()
        return True


class AdaptiveRuleRepository:
    """Repository for adaptive rules."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_adaptive_rule(self, rule_data: AdaptiveRuleCreate) -> AdaptiveRule:
        """Create a new adaptive rule.

        Args:
            rule_data: Adaptive rule data

        Returns:
            Created adaptive rule
        """
        rule = AdaptiveRule(
            base_rule_id=rule_data.base_rule_id,
            name=rule_data.name,
            description=rule_data.description,
            rule_type=rule_data.rule_type,
            conditions=rule_data.conditions,
            actions=rule_data.actions,
            confidence=rule_data.confidence,
            is_active=rule_data.is_active,
            adaptive_metadata=rule_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(rule)
        await self.session.flush()
        await self.session.refresh(rule)
        return rule

    async def get_adaptive_rule(self, rule_id: int) -> Optional[AdaptiveRule]:
        """Get an adaptive rule by ID.

        Args:
            rule_id: Adaptive rule ID

        Returns:
            Adaptive rule or None if not found
        """
        result = await self.session.execute(
            select(AdaptiveRule).where(AdaptiveRule.id == rule_id)
        )
        rule: Optional[AdaptiveRule] = result.scalars().first()
        return rule

    async def get_adaptive_rules_by_type(
        self, rule_type: str, active_only: bool = True
    ) -> List[AdaptiveRule]:
        """Get adaptive rules by type.

        Args:
            rule_type: Rule type
            active_only: Whether to return only active rules

        Returns:
            List of adaptive rules
        """
        query = select(AdaptiveRule).where(AdaptiveRule.rule_type == rule_type)
        if active_only:
            query = query.where(AdaptiveRule.is_active)
        # Order by effectiveness score (higher first)
        query = query.order_by(AdaptiveRule.effectiveness_score.desc())
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_adaptive_rules_by_base_rule(
        self, base_rule_id: int, active_only: bool = True
    ) -> List[AdaptiveRule]:
        """Get adaptive rules by base rule ID.

        Args:
            base_rule_id: Base rule ID
            active_only: Whether to return only active rules

        Returns:
            List of adaptive rules
        """
        query = select(AdaptiveRule).where(AdaptiveRule.base_rule_id == base_rule_id)
        if active_only:
            query = query.where(AdaptiveRule.is_active)
        # Order by version (higher first)
        query = query.order_by(AdaptiveRule.version.desc())
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_most_effective_rules(
        self, limit: int = 10, active_only: bool = True
    ) -> List[AdaptiveRule]:
        """Get the most effective adaptive rules.

        Args:
            limit: Maximum number of rules to return
            active_only: Whether to return only active rules

        Returns:
            List of adaptive rules ordered by effectiveness
        """
        query = select(AdaptiveRule)
        if active_only:
            query = query.where(AdaptiveRule.is_active)
        # Order by effectiveness score (higher first)
        query = query.order_by(AdaptiveRule.effectiveness_score.desc()).limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_adaptive_rule(
        self, rule_id: int, update_data: dict
    ) -> Optional[AdaptiveRule]:
        """Update an adaptive rule.

        Args:
            rule_id: Adaptive rule ID
            update_data: Update data dictionary

        Returns:
            Updated adaptive rule or None if not found
        """
        db_rule = await self.get_adaptive_rule(rule_id)
        if not db_rule:
            return None

        # Update fields if provided
        for key, value in update_data.items():
            if hasattr(db_rule, key):
                setattr(db_rule, key, value)

        db_rule.updated_at = datetime.utcnow()
        self.session.add(db_rule)
        await self.session.flush()
        await self.session.refresh(db_rule)
        return db_rule

    async def update_rule_effectiveness(
        self, rule_id: int, success: bool
    ) -> Optional[AdaptiveRule]:
        """Update an adaptive rule's effectiveness based on success or failure.

        Args:
            rule_id: Adaptive rule ID
            success: Whether the rule was successful

        Returns:
            Updated adaptive rule or None if not found
        """
        db_rule = await self.get_adaptive_rule(rule_id)
        if not db_rule:
            return None

        # Update success or failure count
        if success:
            db_rule.success_count += 1
        else:
            db_rule.failure_count += 1

        # Calculate new effectiveness score
        total_executions = db_rule.success_count + db_rule.failure_count
        if total_executions > 0:
            db_rule.effectiveness_score = db_rule.success_count / total_executions
        else:
            db_rule.effectiveness_score = 0.5  # Default score for no executions

        db_rule.updated_at = datetime.utcnow()
        self.session.add(db_rule)
        await self.session.flush()
        await self.session.refresh(db_rule)
        return db_rule

    async def create_evolved_rule(
        self, base_rule_id: int, modifications: dict
    ) -> Optional[AdaptiveRule]:
        """Create a new evolved version of an existing rule.

        Args:
            base_rule_id: ID of the rule to evolve
            modifications: Dictionary of modifications to apply

        Returns:
            Newly created evolved rule or None if base rule not found
        """
        base_rule = await self.get_adaptive_rule(base_rule_id)
        if not base_rule:
            return None

        # Get the latest version of this rule lineage
        descendants = await self.get_adaptive_rules_by_base_rule(
            base_rule.base_rule_id or base_rule_id
        )
        latest_version = max([r.version for r in descendants] + [base_rule.version])

        # Create a new rule with modifications applied
        new_rule_data = AdaptiveRuleCreate(
            base_rule_id=base_rule.base_rule_id or base_rule_id,
            name=f"{base_rule.name} (Evolved v{latest_version + 1})",
            description=base_rule.description,
            rule_type=base_rule.rule_type,
            conditions=dict(base_rule.conditions),  # Create a copy
            actions=dict(base_rule.actions),  # Create a copy
            confidence=base_rule.confidence,
            is_active=True,
            metadata={
                "evolved_from": base_rule_id,
                "evolution_reason": modifications.get("reason", "Rule evolution"),
                "parent_effectiveness": base_rule.effectiveness_score,
                **base_rule.adaptive_metadata,
            },
        )

        # Apply modifications
        if "conditions" in modifications:
            for k, v in modifications["conditions"].items():
                new_rule_data.conditions[k] = v
        if "actions" in modifications:
            for k, v in modifications["actions"].items():
                new_rule_data.actions[k] = v
        if "name" in modifications:
            new_rule_data.name = modifications["name"]
        if "description" in modifications:
            new_rule_data.description = modifications["description"]

        # Create the new rule
        new_rule = await self.create_adaptive_rule(new_rule_data)

        # Set the version
        await self.update_adaptive_rule(new_rule.id, {"version": latest_version + 1})

        # Deactivate the previous rule if requested
        if modifications.get("deactivate_parent", True):
            await self.update_adaptive_rule(base_rule_id, {"is_active": False})

        return await self.get_adaptive_rule(new_rule.id)

    async def delete_adaptive_rule(self, rule_id: int) -> bool:
        """Delete an adaptive rule.

        Args:
            rule_id: Adaptive rule ID

        Returns:
            True if deleted, False if not found
        """
        db_rule = await self.get_adaptive_rule(rule_id)
        if not db_rule:
            return False

        await self.session.delete(db_rule)
        await self.session.flush()
        return True


class ContextualScoreRepository:
    """Repository for contextual scoring rules."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session

    async def create_score(self, score_data: ContextualScoreCreate) -> ContextualScore:
        """Create a new contextual scoring rule.

        Args:
            score_data: Contextual score data

        Returns:
            Created contextual score
        """
        score = ContextualScore(
            name=score_data.name,
            description=score_data.description,
            context_type=score_data.context_type,
            context_definition=score_data.context_definition,
            scoring_function=score_data.scoring_function,
            is_active=score_data.is_active,
            score_metadata=score_data.metadata,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(score)
        await self.session.flush()
        await self.session.refresh(score)
        return score

    async def get_score(self, score_id: int) -> Optional[ContextualScore]:
        """Get a contextual score by ID.

        Args:
            score_id: Contextual score ID

        Returns:
            Contextual score or None if not found
        """
        result = await self.session.execute(
            select(ContextualScore).where(ContextualScore.id == score_id)
        )
        score: Optional[ContextualScore] = result.scalars().first()
        return score

    async def get_scores_by_context_type(
        self, context_type: ContextType, active_only: bool = True
    ) -> List[ContextualScore]:
        """Get contextual scores by context type.

        Args:
            context_type: Context type
            active_only: Whether to return only active scores

        Returns:
            List of contextual scores
        """
        query = select(ContextualScore).where(
            ContextualScore.context_type == context_type
        )
        if active_only:
            query = query.where(ContextualScore.is_active)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_scores(self) -> List[ContextualScore]:
        """Get all active contextual scores.

        Returns:
            List of active contextual scores
        """
        result = await self.session.execute(
            select(ContextualScore).where(ContextualScore.is_active)
        )
        return list(result.scalars().all())

    async def update_score(
        self, score_id: int, update_data: dict
    ) -> Optional[ContextualScore]:
        """Update a contextual score.

        Args:
            score_id: Contextual score ID
            update_data: Update data dictionary

        Returns:
            Updated contextual score or None if not found
        """
        db_score = await self.get_score(score_id)
        if not db_score:
            return None

        # Update fields if provided
        for key, value in update_data.items():
            if hasattr(db_score, key):
                setattr(db_score, key, value)

        db_score.updated_at = datetime.utcnow()
        self.session.add(db_score)
        await self.session.flush()
        await self.session.refresh(db_score)
        return db_score

    async def delete_score(self, score_id: int) -> bool:
        """Delete a contextual score.

        Args:
            score_id: Contextual score ID

        Returns:
            True if deleted, False if not found
        """
        db_score = await self.get_score(score_id)
        if not db_score:
            return False

        await self.session.delete(db_score)
        await self.session.flush()
        return True
