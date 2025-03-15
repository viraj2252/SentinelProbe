"""Models for the Reporting Engine."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from sqlalchemy import JSON, DateTime
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelprobe.core.db import Base


class ReportFormat(Enum):
    """Report format types."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    TEXT = "text"


class ReportType(Enum):
    """Report type categories."""

    FULL = "full"
    SUMMARY = "summary"
    VULNERABILITY = "vulnerability"
    RECONNAISSANCE = "reconnaissance"
    CUSTOM = "custom"


class ReportStatus(Enum):
    """Report generation status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Report(Base):
    """Report database model."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    report_type: Mapped[ReportType] = mapped_column(SQLAEnum(ReportType))
    report_format: Mapped[ReportFormat] = mapped_column(SQLAEnum(ReportFormat))
    status: Mapped[ReportStatus] = mapped_column(SQLAEnum(ReportStatus))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    content_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    report_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )

    # Relationships
    job = relationship("Job", back_populates="reports")


class VulnerabilityFindings(BaseModel):
    """Pydantic model for vulnerability findings in reports."""

    id: int
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    affected_targets: List[Dict[str, Any]]
    remediation_steps: Optional[List[str]] = None
    references: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class ReportTemplate(BaseModel):
    """Pydantic model for report templates."""

    name: str
    description: str
    template_format: ReportFormat
    template_type: ReportType
    content: str
    metadata: Optional[Dict[str, Any]] = None


class ReportRequest(BaseModel):
    """Pydantic model for report generation requests."""

    job_id: int
    report_type: ReportType
    report_format: ReportFormat
    title: str
    description: Optional[str] = None
    template_name: Optional[str] = None
    custom_sections: Optional[List[str]] = None
    include_findings: Optional[bool] = True
    include_recommendations: Optional[bool] = True
    metadata: Optional[Dict[str, Any]] = None


class ReportData(BaseModel):
    """Pydantic model for report data."""

    report_id: int
    job_id: int
    title: str
    description: Optional[str] = None
    summary: Optional[str] = None
    findings: Optional[List[VulnerabilityFindings]] = None
    reconnaissance_data: Optional[Dict[str, Any]] = None
    remediation_summary: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
