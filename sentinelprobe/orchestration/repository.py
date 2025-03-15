"""Repository for the Orchestration Engine."""

import json
from datetime import datetime
from typing import List, Optional, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.logging import get_logger
from sentinelprobe.orchestration.models import Job, JobStatus, JobType, Task, TaskStatus

logger = get_logger()


class JobRepository:
    """Repository for job operations.

    Attributes:
        session: Database session.
    """

    def __init__(self, session: AsyncSession):
        """Initialize repository.

        Args:
            session: Database session.
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
        """Create a new job.

        Args:
            name: Job name.
            job_type: Type of job.
            target: Target system.
            description: Job description.
            config: Job configuration.

        Returns:
            Job: Created job.
        """
        job = Job(
            name=name,
            job_type=job_type,
            target=target,
            description=description,
            config=json.dumps(config) if config else None,
        )
        self.session.add(job)
        await self.session.commit()
        await self.session.refresh(job)
        logger.info(f"Created job: {job.id} - {job.name}")
        return job

    async def get_job(self, job_id: int) -> Optional[Job]:
        """Get a job by ID.

        Args:
            job_id: Job ID.

        Returns:
            Optional[Job]: Found job or None.
        """
        result = await self.session.execute(select(Job).filter(Job.id == job_id))
        return result.scalars().first()

    async def get_jobs(
        self, limit: int = 100, offset: int = 0, status: Optional[JobStatus] = None
    ) -> List[Job]:
        """Get jobs with optional filtering.

        Args:
            limit: Maximum number of jobs to return.
            offset: Number of jobs to skip.
            status: Filter by status.

        Returns:
            List[Job]: List of jobs.
        """
        query = select(Job)
        if status:
            query = query.filter(Job.status == status)
        query = query.order_by(Job.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_job(
        self,
        job_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[JobStatus] = None,
        config: Optional[dict] = None,
    ) -> Optional[Job]:
        """Update a job.

        Args:
            job_id: Job ID.
            name: Job name.
            description: Job description.
            status: Job status.
            config: Job configuration.

        Returns:
            Optional[Job]: Updated job or None.
        """
        job = await self.get_job(job_id)
        if not job:
            return None

        if name is not None:
            job.name = name
        if description is not None:
            job.description = description
        if status is not None:
            job.status = status
            if status == JobStatus.RUNNING and not job.started_at:
                job.started_at = datetime.utcnow()
            elif status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                job.completed_at = datetime.utcnow()
        if config is not None:
            job.config = json.dumps(config)

        await self.session.commit()
        await self.session.refresh(job)
        logger.info(f"Updated job: {job.id} - {job.name}")
        return job

    async def delete_job(self, job_id: int) -> bool:
        """Delete a job.

        Args:
            job_id: Job ID.

        Returns:
            bool: True if deleted, False if not found.
        """
        job = await self.get_job(job_id)
        if not job:
            return False

        await self.session.delete(job)
        await self.session.commit()
        logger.info(f"Deleted job: {job_id}")
        return True


class TaskRepository:
    """Repository for task operations.

    Attributes:
        session: Database session.
    """

    def __init__(self, session: AsyncSession):
        """Initialize repository.

        Args:
            session: Database session.
        """
        self.session = session

    async def create_task(
        self, job_id: int, name: str, description: Optional[str] = None
    ) -> Optional[Task]:
        """Create a new task.

        Args:
            job_id: Related job ID.
            name: Task name.
            description: Task description.

        Returns:
            Optional[Task]: Created task or None if job not found.
        """
        # Check if job exists
        result = await self.session.execute(select(Job).filter(Job.id == job_id))
        job = result.scalars().first()
        if not job:
            return None

        task = Task(job_id=job_id, name=name, description=description)
        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)
        logger.info(f"Created task: {task.id} - {task.name} for job {job_id}")
        return task

    async def get_task(self, task_id: int) -> Optional[Task]:
        """Get a task by ID.

        Args:
            task_id: Task ID.

        Returns:
            Optional[Task]: Found task or None.
        """
        result = await self.session.execute(select(Task).filter(Task.id == task_id))
        return result.scalars().first()

    async def get_tasks_by_job(self, job_id: int) -> List[Task]:
        """Get tasks for a job.

        Args:
            job_id: Job ID.

        Returns:
            List[Task]: List of tasks.
        """
        result = await self.session.execute(select(Task).filter(Task.job_id == job_id))
        return list(result.scalars().all())

    async def update_task(
        self,
        task_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[TaskStatus] = None,
        result: Optional[dict] = None,
    ) -> Optional[Task]:
        """Update a task.

        Args:
            task_id: Task ID.
            name: Task name.
            description: Task description.
            status: Task status.
            result: Task result.

        Returns:
            Optional[Task]: Updated task or None.
        """
        task = await self.get_task(task_id)
        if not task:
            return None

        if name is not None:
            task.name = name
        if description is not None:
            task.description = description
        if status is not None:
            task.status = status
            if status == TaskStatus.RUNNING and not task.started_at:
                task.started_at = datetime.utcnow()
            elif status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
                task.completed_at = datetime.utcnow()
        if result is not None:
            task.result = json.dumps(result)

        await self.session.commit()
        await self.session.refresh(task)
        logger.info(f"Updated task: {task.id} - {task.name}")
        return task

    async def delete_task(self, task_id: int) -> bool:
        """Delete a task.

        Args:
            task_id: Task ID.

        Returns:
            bool: True if deleted, False if not found.
        """
        task = await self.get_task(task_id)
        if not task:
            return False

        await self.session.delete(task)
        await self.session.commit()
        logger.info(f"Deleted task: {task_id}")
        return True 