"""Models for the Orchestration Engine."""

import enum
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pydantic import BaseModel
from sqlalchemy import JSON, DateTime
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelprobe.core.db import Base

if TYPE_CHECKING:
    from sentinelprobe.reporting.models import Report


class JobType(enum.Enum):
    """Job type enum."""

    SCAN = "scan"
    MONITOR = "monitor"
    ALERT = "alert"
    REPORT = "report"


class JobStatus(enum.Enum):
    """Job status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobExecution(Base):
    """Job execution model."""

    __tablename__ = "job_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[JobStatus] = mapped_column(
        SQLAEnum(JobStatus), nullable=False, default=JobStatus.PENDING
    )
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Relationships
    job: Mapped["Job"] = relationship("Job", back_populates="executions")


class Job(Base):
    """Job model for orchestration."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    job_type: Mapped[JobType] = mapped_column(SQLAEnum(JobType), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        SQLAEnum(JobStatus), nullable=False, default=JobStatus.PENDING
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    schedule: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    tasks: Mapped[List["Task"]] = relationship(
        "Task", back_populates="job", cascade="all, delete-orphan"
    )
    executions: Mapped[List[JobExecution]] = relationship(
        "JobExecution", back_populates="job", cascade="all, delete-orphan"
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="job", cascade="all, delete-orphan"
    )


class TaskStatus(enum.Enum):
    """Task status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Task(Base):
    """Task model for orchestration."""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[TaskStatus] = mapped_column(
        SQLAEnum(TaskStatus), nullable=False, default=TaskStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Relationships
    job: Mapped[Job] = relationship("Job", back_populates="tasks")


# Pydantic models for API
class JobCreate(BaseModel):
    """Job creation model."""

    name: str
    job_type: JobType
    target: str
    description: Optional[str] = None
    config: Dict[str, Any] = {}


class JobUpdate(BaseModel):
    """Job update model."""

    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[JobStatus] = None
    config: Optional[Dict[str, Any]] = None


class JobResponse(BaseModel):
    """Job response model."""

    id: int
    name: str
    description: Optional[str]
    job_type: JobType
    status: JobStatus
    target: str
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class TaskCreate(BaseModel):
    """Task creation model."""

    job_id: int
    name: str
    description: Optional[str] = None


class TaskUpdate(BaseModel):
    """Task update model."""

    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TaskStatus] = None
    result: Optional[Dict[str, Any]] = None


class TaskResponse(BaseModel):
    """Task response model."""

    id: int
    job_id: int
    name: str
    description: Optional[str]
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    result: Optional[Dict[str, Any]]
