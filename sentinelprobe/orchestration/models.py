"""Models for the Orchestration Engine."""

import enum
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelprobe.core.db import Base


class JobStatus(enum.Enum):
    """Job status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobType(enum.Enum):
    """Job type enum."""

    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    FULL_TEST = "full_test"


class Job(Base):
    """Job model for the Orchestration Engine.

    Attributes:
        id: Job ID.
        name: Job name.
        description: Job description.
        job_type: Type of job.
        status: Job status.
        target: Target system.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        started_at: Start timestamp.
        completed_at: Completion timestamp.
        config: Job configuration.
        tasks: Related tasks.
    """

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    job_type: Mapped[JobType] = mapped_column(Enum(JobType), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), nullable=False, default=JobStatus.PENDING
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    tasks: Mapped[List["Task"]] = relationship("Task", back_populates="job", cascade="all, delete-orphan")


class TaskStatus(enum.Enum):
    """Task status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Task(Base):
    """Task model for the Orchestration Engine.

    Attributes:
        id: Task ID.
        job_id: Related job ID.
        name: Task name.
        description: Task description.
        status: Task status.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        started_at: Start timestamp.
        completed_at: Completion timestamp.
        result: Task result.
        job: Related job.
    """

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(Integer, ForeignKey("jobs.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus), nullable=False, default=TaskStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    job: Mapped[Job] = relationship("Job", back_populates="tasks")


# Pydantic models for API
class JobBase(BaseModel):
    """Base model for job data.

    Attributes:
        name: Job name.
        description: Job description.
        job_type: Type of job.
        target: Target system.
        config: Job configuration.
    """

    name: str
    description: Optional[str] = None
    job_type: JobType
    target: str
    config: Optional[dict] = None


class JobCreate(JobBase):
    """Model for creating a job."""

    pass


class JobUpdate(BaseModel):
    """Model for updating a job.

    Attributes:
        name: Job name.
        description: Job description.
        status: Job status.
        config: Job configuration.
    """

    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[JobStatus] = None
    config: Optional[dict] = None


class TaskBase(BaseModel):
    """Base model for task data.

    Attributes:
        name: Task name.
        description: Task description.
    """

    name: str
    description: Optional[str] = None


class TaskCreate(TaskBase):
    """Model for creating a task.

    Attributes:
        job_id: Related job ID.
    """

    job_id: int


class TaskUpdate(BaseModel):
    """Model for updating a task.

    Attributes:
        name: Task name.
        description: Task description.
        status: Task status.
        result: Task result.
    """

    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TaskStatus] = None
    result: Optional[dict] = None


class TaskResponse(TaskBase):
    """Model for task response.

    Attributes:
        id: Task ID.
        job_id: Related job ID.
        status: Task status.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        started_at: Start timestamp.
        completed_at: Completion timestamp.
        result: Task result.
    """

    id: int
    job_id: int
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[dict] = None

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class JobResponse(JobBase):
    """Model for job response.

    Attributes:
        id: Job ID.
        status: Job status.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        started_at: Start timestamp.
        completed_at: Completion timestamp.
        tasks: Related tasks.
    """

    id: int
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tasks: List[TaskResponse] = []

    class Config:
        """Pydantic configuration."""

        from_attributes = True 