"""Repository classes for the AI Decision Engine."""

from datetime import datetime
from typing import Any, Dict, List, Optional, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.ai_decision.models import (
    ConfidenceLevel,
    DecisionRule,
    DecisionRuleCreate,
    DecisionRuleUpdate,
    KnowledgeItem,
    KnowledgeItemCreate,
    KnowledgeItemUpdate,
    TestStrategy,
    TestStrategyCreate,
    TestStrategyUpdate,
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
