"""Mock repository implementations for testing."""

from datetime import datetime, timezone
from typing import List, Optional

from sentinelprobe.orchestration.models import Job, JobStatus, JobType, Task, TaskStatus


class MockJobRepository:
    """Mock implementation of JobRepository for testing."""

    def __init__(self, session):
        """Initialize with mock session."""
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
            status=JobStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
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
        for job in self.session.jobs:
            if job.id == job_id:
                return job
        return None

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
        filtered_jobs = self.session.jobs

        if status is not None:
            filtered_jobs = [job for job in filtered_jobs if job.status == status]

        # Apply offset and limit
        return filtered_jobs[offset : offset + limit]

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
            name: New job name
            description: New job description
            status: New job status
            config: New job configuration

        Returns:
            Optional[Job]: Updated job or None
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
        if config is not None:
            job.config = config

        job.updated_at = datetime.now(timezone.utc)
        await self.session.commit()
        return job

    async def delete_job(self, job_id: int) -> bool:
        """
        Delete a job.

        Args:
            job_id: Job ID

        Returns:
            bool: True if deleted, False if not found
        """
        for i, job in enumerate(self.session.jobs):
            if job.id == job_id:
                self.session.jobs.pop(i)
                await self.session.commit()
                return True
        return False


class MockTaskRepository:
    """Mock implementation of TaskRepository for testing."""

    def __init__(self, session):
        """Initialize with mock session."""
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
            job_id: Job ID
            name: Task name
            description: Optional task description

        Returns:
            Optional[Task]: Created task or None if job not found
        """
        # Verify job exists
        job_exists = False
        for job in self.session.jobs:
            if job.id == job_id:
                job_exists = True
                break

        if not job_exists:
            return None

        task = Task(
            job_id=job_id,
            name=name,
            description=description,
            status=TaskStatus.PENDING,
            created_at=datetime.now(timezone.utc),
        )

        self.session.add(task)
        await self.session.commit()
        return task

    async def get_task(self, task_id: int) -> Optional[Task]:
        """
        Get a task by ID.

        Args:
            task_id: Task ID

        Returns:
            Optional[Task]: Found task or None
        """
        for task in self.session.tasks:
            if task.id == task_id:
                return task
        return None

    async def get_tasks_by_job(self, job_id: int) -> List[Task]:
        """
        Get tasks for a job.

        Args:
            job_id: Job ID

        Returns:
            List[Task]: List of tasks
        """
        return [task for task in self.session.tasks if task.job_id == job_id]

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
            name: New task name
            description: New task description
            status: New task status
            result: Task result data

        Returns:
            Optional[Task]: Updated task or None
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

            # Update timestamps based on status
            if status == TaskStatus.RUNNING and not task.started_at:
                task.started_at = datetime.now(timezone.utc)
            elif (
                status
                in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
                and not task.completed_at
            ):
                task.completed_at = datetime.now(timezone.utc)

        if result is not None:
            task.result = result

        task.updated_at = datetime.now(timezone.utc)
        await self.session.commit()
        return task

    async def delete_task(self, task_id: int) -> bool:
        """
        Delete a task.

        Args:
            task_id: Task ID

        Returns:
            bool: True if deleted, False if not found
        """
        for i, task in enumerate(self.session.tasks):
            if task.id == task_id:
                self.session.tasks.pop(i)
                await self.session.commit()
                return True
        return False
