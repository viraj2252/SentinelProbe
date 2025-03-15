"""Repository for the Orchestration Engine."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.logging import get_logger
from sentinelprobe.orchestration.models import Job, JobStatus, JobType, Task, TaskStatus

logger = get_logger(__name__)


class JobRepository:
    """Repository for job operations."""

    def __init__(self, session: AsyncSession):
        """
        Initialize repository.

        Args:
            session: Database session
        """
        self.session = session

    async def create_job(
        self,
        name: str,
        job_type: JobType,
        target: str,
        description: Optional[str] = None,
        config: Optional[dict] = None,
    ) -> Job:
        """
        Create a new job.

        Args:
            name: Job name
            job_type: Type of job
            target: Target system
            description: Optional job description
            config: Optional job configuration

        Returns:
            Job: Created job
        """
        job = Job(
            name=name,
            job_type=job_type,
            target=target,
            description=description,
            config=config or {},
        )

        self.session.add(job)
        await self.session.commit()
        await self.session.refresh(job)

        return job

    async def get_job(self, job_id: int) -> Optional[Job]:
        """
        Get a job by ID.

        Args:
            job_id: Job ID

        Returns:
            Optional[Job]: Found job or None
        """
        stmt = select(Job).where(Job.id == job_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_jobs(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[JobStatus] = None,
    ) -> List[Job]:
        """
        Get jobs with optional filtering.

        Args:
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip
            status: Filter by status

        Returns:
            List[Job]: List of jobs
        """
        stmt = select(Job)

        if status:
            stmt = stmt.where(Job.status == status)

        stmt = stmt.limit(limit).offset(offset)
        result = await self.session.execute(stmt)

        return list(result.scalars().all())

    async def update_job(
        self,
        job_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[JobStatus] = None,
        config: Optional[dict] = None,
    ) -> Optional[Job]:
        """
        Update a job.

        Args:
            job_id: Job ID
            name: Optional new name
            description: Optional new description
            status: Optional new status
            config: Optional new configuration

        Returns:
            Optional[Job]: Updated job or None if not found
        """
        # Get the job
        job = await self.get_job(job_id)
        if not job:
            return None

        # Update fields if provided
        if name is not None:
            job.name = name
        if description is not None:
            job.description = description
        if status is not None:
            job.status = status
        if config is not None:
            job.config = config

        # Update timestamp
        job.updated_at = datetime.utcnow()

        await self.session.commit()
        await self.session.refresh(job)

        return job

    async def delete_job(self, job_id: int) -> bool:
        """
        Delete a job.

        Args:
            job_id: Job ID

        Returns:
            bool: True if deleted, False if not found
        """
        # Get the job
        job = await self.get_job(job_id)
        if not job:
            return False

        # Delete the job
        await self.session.delete(job)
        await self.session.commit()

        return True

    async def update_job_status(self, job_id: int, status: JobStatus) -> Optional[Job]:
        """
        Update job status.

        Args:
            job_id: Job ID
            status: New job status

        Returns:
            Optional[Job]: Updated job or None if not found
        """
        stmt = (
            update(Job)
            .where(Job.id == job_id)
            .values(status=status, updated_at=datetime.utcnow())
            .returning(Job)
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.scalar_one_or_none()


class TaskRepository:
    """Repository for task operations."""

    def __init__(self, session: AsyncSession):
        """
        Initialize repository.

        Args:
            session: Database session
        """
        self.session = session

    async def create_task(
        self,
        job_id: int,
        name: str,
        description: Optional[str] = None,
    ) -> Optional[Task]:
        """
        Create a new task.

        Args:
            job_id: Related job ID
            name: Task name
            description: Optional task description

        Returns:
            Optional[Task]: Created task or None if job not found
        """
        # Check if job exists
        stmt = select(Job).where(Job.id == job_id)
        result = await self.session.execute(stmt)
        job = result.scalar_one_or_none()

        if not job:
            return None

        # Create task
        task = Task(
            job_id=job_id,
            name=name,
            description=description,
        )

        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)

        return task

    async def get_task(self, task_id: int) -> Optional[Task]:
        """
        Get a task by ID.

        Args:
            task_id: Task ID

        Returns:
            Optional[Task]: Found task or None
        """
        stmt = select(Task).where(Task.id == task_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_tasks_by_job(self, job_id: int) -> List[Task]:
        """
        Get tasks for a job.

        Args:
            job_id: Job ID

        Returns:
            List[Task]: List of tasks
        """
        stmt = select(Task).where(Task.job_id == job_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_task(
        self,
        task_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[TaskStatus] = None,
        result: Optional[dict] = None,
    ) -> Optional[Task]:
        """
        Update a task.

        Args:
            task_id: Task ID
            name: Optional new name
            description: Optional new description
            status: Optional new status
            result: Optional new result

        Returns:
            Optional[Task]: Updated task or None if not found
        """
        # Get the task
        task = await self.get_task(task_id)
        if not task:
            return None

        # Update fields if provided
        if name is not None:
            task.name = name
        if description is not None:
            task.description = description
        if status is not None:
            task.status = status
            # Update timestamps based on status
            if status == TaskStatus.RUNNING and not task.started_at:
                task.started_at = datetime.utcnow()
            elif status in (
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            ):
                task.completed_at = datetime.utcnow()
        if result is not None:
            task.result = result

        await self.session.commit()
        await self.session.refresh(task)

        return task

    async def delete_task(self, task_id: int) -> bool:
        """
        Delete a task.

        Args:
            task_id: Task ID

        Returns:
            bool: True if deleted, False if not found
        """
        # Get the task
        task = await self.get_task(task_id)
        if not task:
            return False

        # Delete the task
        await self.session.delete(task)
        await self.session.commit()

        return True
