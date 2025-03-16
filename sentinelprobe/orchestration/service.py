"""Service for the Orchestration Engine."""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.logging import get_logger
from sentinelprobe.orchestration.models import (
    Job,
    JobCreate,
    JobResponse,
    JobStatus,
    JobUpdate,
    Task,
    TaskCreate,
    TaskResponse,
    TaskStatus,
    TaskUpdate,
)
from sentinelprobe.orchestration.repository import JobRepository, TaskRepository

logger = get_logger(__name__)


class OrchestrationService:
    """Service for orchestration operations.

    Attributes:
        session: Database session.
        job_repository: Repository for job operations.
        task_repository: Repository for task operations.
    """

    def __init__(self, session: AsyncSession):
        """Initialize service.

        Args:
            session: Database session.
        """
        self.session = session
        self.job_repository = JobRepository(session)
        self.task_repository = TaskRepository(session)

    async def create_job(self, job_data: JobCreate) -> JobResponse:
        """Create a new job.

        Args:
            job_data: Job data.

        Returns:
            JobResponse: Created job.
        """
        job = await self.job_repository.create_job(
            name=job_data.name,
            job_type=job_data.job_type,
            target=job_data.target,
            description=job_data.description,
            config=dict(job_data.config) if job_data.config else {},
        )
        return self._job_to_response(job)

    async def get_job(self, job_id: int) -> Optional[JobResponse]:
        """Get a job by ID.

        Args:
            job_id: Job ID.

        Returns:
            Optional[JobResponse]: Found job or None.
        """
        job = await self.job_repository.get_job(job_id)
        if not job:
            return None
        return self._job_to_response(job)

    async def get_jobs(
        self, limit: int = 100, offset: int = 0, status: Optional[JobStatus] = None
    ) -> List[JobResponse]:
        """Get jobs with optional filtering.

        Args:
            limit: Maximum number of jobs to return.
            offset: Number of jobs to skip.
            status: Filter by status.

        Returns:
            List[JobResponse]: List of jobs.
        """
        jobs = await self.job_repository.get_jobs(limit, offset, status)
        return [self._job_to_response(job) for job in jobs]

    async def update_job(
        self, job_id: int, job_data: JobUpdate
    ) -> Optional[JobResponse]:
        """Update a job.

        Args:
            job_id: Job ID.
            job_data: Job data.

        Returns:
            Optional[JobResponse]: Updated job or None.
        """
        job = await self.job_repository.update_job(
            job_id=job_id,
            name=job_data.name,
            description=job_data.description,
            status=job_data.status,
            config=job_data.config,
        )
        if not job:
            return None
        return self._job_to_response(job)

    async def delete_job(self, job_id: int) -> bool:
        """Delete a job.

        Args:
            job_id: Job ID.

        Returns:
            bool: True if deleted, False if not found.
        """
        return await self.job_repository.delete_job(job_id)

    async def create_task(self, task_data: TaskCreate) -> Optional[TaskResponse]:
        """Create a new task.

        Args:
            task_data: Task data.

        Returns:
            Optional[TaskResponse]: Created task or None if job not found.
        """
        task = await self.task_repository.create_task(
            job_id=task_data.job_id,
            name=task_data.name,
            description=task_data.description,
        )
        if not task:
            return None
        return self._task_to_response(task)

    async def get_task(self, task_id: int) -> Optional[TaskResponse]:
        """Get a task by ID.

        Args:
            task_id: Task ID.

        Returns:
            Optional[TaskResponse]: Found task or None.
        """
        task = await self.task_repository.get_task(task_id)
        if not task:
            return None
        return self._task_to_response(task)

    async def get_tasks_by_job(self, job_id: int) -> List[TaskResponse]:
        """Get tasks for a job.

        Args:
            job_id: Job ID.

        Returns:
            List[TaskResponse]: List of tasks.
        """
        tasks = await self.task_repository.get_tasks_by_job(job_id)
        return [self._task_to_response(task) for task in tasks]

    async def update_task(
        self, task_id: int, task_data: TaskUpdate
    ) -> Optional[TaskResponse]:
        """Update a task.

        Args:
            task_id: Task ID.
            task_data: Task data.

        Returns:
            Optional[TaskResponse]: Updated task or None.
        """
        task = await self.task_repository.update_task(
            task_id=task_id,
            name=task_data.name,
            description=task_data.description,
            status=task_data.status,
            result=task_data.result,
        )
        if not task:
            return None
        return self._task_to_response(task)

    async def delete_task(self, task_id: int) -> bool:
        """Delete a task.

        Args:
            task_id: Task ID.

        Returns:
            bool: True if deleted, False if not found.
        """
        return await self.task_repository.delete_task(task_id)

    async def start_job(self, job_id: int) -> Optional[JobResponse]:
        """Start a job.

        Args:
            job_id: Job ID.

        Returns:
            Optional[JobResponse]: Updated job or None.
        """
        job = await self.job_repository.update_job(
            job_id=job_id,
            status=JobStatus.RUNNING,
        )
        if not job:
            return None

        # TODO: Implement actual job execution logic
        # This would involve creating tasks and dispatching them to appropriate modules

        return self._job_to_response(job)

    async def cancel_job(self, job_id: int) -> Optional[JobResponse]:
        """Cancel a job.

        Args:
            job_id: Job ID.

        Returns:
            Optional[JobResponse]: Updated job or None.
        """
        job = await self.job_repository.update_job(
            job_id=job_id,
            status=JobStatus.CANCELLED,
        )
        if not job:
            return None

        # Cancel all pending and running tasks
        tasks = await self.task_repository.get_tasks_by_job(job_id)
        for task in tasks:
            if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                await self.task_repository.update_task(
                    task_id=task.id,
                    status=TaskStatus.CANCELLED,
                )

        return self._job_to_response(job)

    def _job_to_response(self, job: Job) -> JobResponse:
        """Convert Job model to JobResponse.

        Args:
            job: Job model.

        Returns:
            JobResponse: Job response.
        """
        return JobResponse(
            id=job.id,
            name=job.name,
            description=job.description,
            job_type=job.job_type,
            status=job.status,
            target=job.target,
            created_at=job.created_at,
            updated_at=job.updated_at,
            config=job.config,
        )

    def _task_to_response(self, task: Task) -> TaskResponse:
        """Convert Task model to TaskResponse.

        Args:
            task: Task model.

        Returns:
            TaskResponse: Task response.
        """
        result = task.result if task.result else None
        return TaskResponse(
            id=task.id,
            job_id=task.job_id,
            name=task.name,
            description=task.description,
            status=task.status,
            created_at=task.created_at,
            started_at=task.started_at,
            completed_at=task.completed_at,
            result=result,
        )
