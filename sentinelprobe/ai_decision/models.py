"""Models for the AI Decision Engine."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Column, DateTime
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy import Float, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelprobe.core.db import Base


class DecisionRuleType(Enum):
    """Types of decision rules."""

    SERVICE_DETECTION = "service_detection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class DecisionRuleSeverity(Enum):
    """Severity levels for decision rules."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrategyPhase(Enum):
    """Strategy phases."""

    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class ConfidenceLevel(Enum):
    """Confidence levels for decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TargetRiskLevel(Enum):
    """Risk levels for targets."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Association table for rules to strategies
rules_strategies = Table(
    "rules_strategies",
    Base.metadata,
    Column("rule_id", ForeignKey("decision_rules.id"), primary_key=True),
    Column("strategy_id", ForeignKey("test_strategies.id"), primary_key=True),
)


class KnowledgeItem(Base):
    """Knowledge item model for storing discovered information."""

    __tablename__ = "knowledge_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("targets.id"), nullable=True
    )
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    value_type: Mapped[str] = mapped_column(String(50), nullable=False)
    string_value: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    int_value: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    float_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    bool_value: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    json_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    confidence: Mapped[ConfidenceLevel] = mapped_column(
        SQLAEnum(ConfidenceLevel), nullable=False, default=ConfidenceLevel.MEDIUM
    )
    item_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class DecisionRule(Base):
    """Decision rule model for the rule-based decision framework."""

    __tablename__ = "decision_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    rule_type: Mapped[DecisionRuleType] = mapped_column(
        SQLAEnum(DecisionRuleType), nullable=False
    )
    severity: Mapped[DecisionRuleSeverity] = mapped_column(
        SQLAEnum(DecisionRuleSeverity), nullable=False
    )
    conditions: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, comment="JSON structure defining rule conditions"
    )
    actions: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, comment="JSON structure defining rule actions"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, comment="Lower numbers = higher priority"
    )
    rule_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    strategies: Mapped[List["TestStrategy"]] = relationship(
        "TestStrategy", secondary=rules_strategies, back_populates="rules"
    )


class TestStrategy(Base):
    """Test strategy model for planning testing approaches."""

    __tablename__ = "test_strategies"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=True)
    phase: Mapped[StrategyPhase] = mapped_column(
        SQLAEnum(StrategyPhase), nullable=False
    )
    parameters: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    strategy_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, comment="Lower numbers = higher priority"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    rules: Mapped[List[DecisionRule]] = relationship(
        "DecisionRule", secondary=rules_strategies, back_populates="strategies"
    )


# Pydantic models for API
class KnowledgeItemCreate(BaseModel):
    """Knowledge item creation model."""

    target_id: Optional[int] = None
    key: str
    value_type: str
    string_value: Optional[str] = None
    int_value: Optional[int] = None
    float_value: Optional[float] = None
    bool_value: Optional[bool] = None
    json_value: Optional[Dict[str, Any]] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeItemUpdate(BaseModel):
    """Knowledge item update model."""

    key: Optional[str] = None
    value_type: Optional[str] = None
    string_value: Optional[str] = None
    int_value: Optional[int] = None
    float_value: Optional[float] = None
    bool_value: Optional[bool] = None
    json_value: Optional[Dict[str, Any]] = None
    confidence: Optional[ConfidenceLevel] = None
    metadata: Optional[Dict[str, Any]] = None


class KnowledgeItemResponse(BaseModel):
    """Knowledge item response model."""

    id: int
    target_id: Optional[int]
    key: str
    value_type: str
    string_value: Optional[str]
    int_value: Optional[int]
    float_value: Optional[float]
    bool_value: Optional[bool]
    json_value: Optional[Dict[str, Any]]
    confidence: ConfidenceLevel
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class DecisionRuleCreate(BaseModel):
    """Decision rule creation model."""

    name: str
    description: str
    rule_type: DecisionRuleType
    severity: DecisionRuleSeverity
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    is_active: bool = True
    priority: int = 100
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionRuleUpdate(BaseModel):
    """Decision rule update model."""

    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[DecisionRuleType] = None
    severity: Optional[DecisionRuleSeverity] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class DecisionRuleResponse(BaseModel):
    """Decision rule response model."""

    id: int
    name: str
    description: str
    rule_type: DecisionRuleType
    severity: DecisionRuleSeverity
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    is_active: bool
    priority: int
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class TestStrategyCreate(BaseModel):
    """Test strategy creation model."""

    job_id: int
    name: str
    description: str
    phase: StrategyPhase
    parameters: Dict[str, Any]
    is_active: bool = True
    priority: int = 100
    metadata: Optional[Dict[str, Any]] = None


class TestStrategyUpdate(BaseModel):
    """Test strategy update model."""

    name: Optional[str] = None
    description: Optional[str] = None
    phase: Optional[StrategyPhase] = None
    parameters: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class TestStrategyResponse(BaseModel):
    """Test strategy response model."""

    id: int
    job_id: int
    name: str
    description: str
    phase: StrategyPhase
    strategy_data: Dict[str, Any]
    is_active: bool
    priority: int
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RuleCondition(BaseModel):
    """Rule condition model for defining conditions in decision rules."""

    condition_type: str
    service_type: Optional[str] = None
    port_number: Optional[int] = None
    port_range: Optional[List[int]] = None
    target_type: Optional[str] = None
    os_type: Optional[str] = None
    risk_level: Optional[TargetRiskLevel] = None
    custom_data: Optional[Dict[str, Any]] = None


class RuleAction(BaseModel):
    """Rule action model for defining actions in decision rules."""

    action_type: str
    scan_types: Optional[List[str]] = None
    scan_parameters: Optional[Dict[str, Any]] = None
    exploit_modules: Optional[List[str]] = None
    exploit_parameters: Optional[Dict[str, Any]] = None
    post_exploit_actions: Optional[List[str]] = None
    reporting_options: Optional[Dict[str, Any]] = None
    target_id: Optional[int] = None
    knowledge_key: Optional[str] = None
    custom_action: Optional[Dict[str, Any]] = None
