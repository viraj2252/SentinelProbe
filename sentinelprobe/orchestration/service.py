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

    async def update_job_status_based_on_tasks(
        self, job_id: int
    ) -> Optional[JobResponse]:
        """Update job status based on the status of its tasks.

        This method checks all tasks for a job and updates the job status accordingly:
        - If all tasks are completed, the job status is set to COMPLETED
        - If any task is failed, the job status is set to FAILED
        - If any task is running, the job status is set to RUNNING
        - If all tasks are cancelled, the job status is set to CANCELLED
        - Otherwise, the job status remains PENDING

        Args:
            job_id: Job ID.

        Returns:
            Optional[JobResponse]: Updated job or None.
        """
        job = await self.job_repository.get_job(job_id)
        if not job:
            logger.warning(
                f"Job {job_id} not found when updating status based on tasks"
            )
            return None

        tasks = await self.task_repository.get_tasks_by_job(job_id)
        if not tasks:
            logger.info(f"No tasks found for job {job_id}, status remains {job.status}")
            return self._job_to_response(job)

        # Count tasks by status
        task_status_counts = {
            TaskStatus.PENDING: 0,
            TaskStatus.RUNNING: 0,
            TaskStatus.COMPLETED: 0,
            TaskStatus.FAILED: 0,
            TaskStatus.CANCELLED: 0,
        }

        for task in tasks:
            task_status_counts[task.status] = task_status_counts.get(task.status, 0) + 1

        logger.info(f"Task status counts for job {job_id}: {task_status_counts}")

        # Determine new job status based on task statuses
        new_status = None

        if task_status_counts[TaskStatus.FAILED] > 0:
            new_status = JobStatus.FAILED
            logger.info(f"Setting job {job_id} status to FAILED due to failed tasks")
        elif task_status_counts[TaskStatus.RUNNING] > 0:
            new_status = JobStatus.RUNNING
            logger.info(f"Setting job {job_id} status to RUNNING due to running tasks")
        elif task_status_counts[TaskStatus.PENDING] > 0:
            new_status = JobStatus.PENDING
            logger.info(f"Job {job_id} status remains PENDING due to pending tasks")
        elif task_status_counts[TaskStatus.CANCELLED] == len(tasks):
            new_status = JobStatus.CANCELLED
            logger.info(
                f"Setting job {job_id} status to CANCELLED as all tasks are cancelled"
            )
        else:
            # All tasks must be completed
            new_status = JobStatus.COMPLETED
            logger.info(
                f"Setting job {job_id} status to COMPLETED as all tasks are completed"
            )

        # Only update if the status has changed
        if new_status and new_status != job.status:
            job = await self.job_repository.update_job(
                job_id=job_id,
                status=new_status,
            )
            logger.info(
                f"Updated job {job_id} status from {job.status} to {new_status}"
            )

        return self._job_to_response(job)

    def _job_to_response(self, job: Job) -> JobResponse:
        """Convert Job model to JobResponse.

        Args:
            job: Job model.

        Returns:
            JobResponse: Job response.
        """
        # Ensure config is properly handled
        config = job.config
        if isinstance(config, str):
            import json

            try:
                config = json.loads(config)
            except json.JSONDecodeError:
                config = {}
        elif not isinstance(config, dict):
            config = {}

        return JobResponse(
            id=job.id,
            name=job.name,
            description=job.description,
            job_type=job.job_type,
            status=job.status,
            target=job.target,
            created_at=job.created_at,
            updated_at=job.updated_at,
            config=config,
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
