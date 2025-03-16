"""Tests for state management and persistence in the orchestration engine."""

import pytest
import pytest_asyncio

from sentinelprobe.orchestration.models import (
    Job,
    JobCreate,
    JobResponse,
    JobStatus,
    JobType,
    JobUpdate,
    Task,
    TaskCreate,
    TaskResponse,
    TaskStatus,
    TaskUpdate,
)
from sentinelprobe.orchestration.repository import JobRepository, TaskRepository
from sentinelprobe.orchestration.service import OrchestrationService
from tests.orchestration.mock_repository import MockJobRepository, MockTaskRepository
from tests.orchestration.mock_session import MockSession


@pytest_asyncio.fixture
async def mock_session():
    """Create a mock SQLAlchemy session."""
    return MockSession()


@pytest_asyncio.fixture
async def job_repository(mock_session):
    """Create a job repository instance for testing."""
    return MockJobRepository(mock_session)


@pytest_asyncio.fixture
async def task_repository(mock_session):
    """Create a task repository instance for testing."""
    return MockTaskRepository(mock_session)


@pytest_asyncio.fixture
async def orchestration_service(mock_session, job_repository, task_repository):
    """Create an orchestration service instance for testing."""
    service = OrchestrationService(mock_session)
    # Replace the repositories with our mock implementations
    service.job_repository = job_repository
    service.task_repository = task_repository
    return service


@pytest_asyncio.fixture
async def test_job(job_repository):
    """Create a test job for state transition tests."""
    return await job_repository.create_job(
        name="State Transition Test Job",
        job_type=JobType.SCAN,
        target="state-test.example.com",
    )


@pytest_asyncio.fixture
async def test_task(task_repository, test_job):
    """Create a test task for state transition tests."""
    return await task_repository.create_task(
        job_id=test_job.id,
        name="State Transition Test Task",
        description="A task for testing state transitions",
    )


class TestJobStateTransitions:
    """Tests for job state transitions."""

    @pytest.mark.asyncio
    async def test_job_lifecycle_transitions(self, job_repository, test_job):
        """Test a full job lifecycle with state transitions."""
        job_id = test_job.id

        # Initial state should be PENDING
        job = await job_repository.get_job(job_id)
        assert job.status == JobStatus.PENDING

        # Update to RUNNING
        job = await job_repository.update_job(
            job_id=job_id,
            status=JobStatus.RUNNING,
        )
        assert job.status == JobStatus.RUNNING

        # Update to COMPLETED
        job = await job_repository.update_job(
            job_id=job_id,
            status=JobStatus.COMPLETED,
        )
        assert job.status == JobStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_job_lifecycle_service(self, orchestration_service):
        """Test a full job lifecycle with state transitions using the service layer."""
        # Create a job
        job_data = JobCreate(
            name="Lifecycle Job",
            job_type=JobType.SCAN,
            target="lifecycle.example.com",
        )
        job = await orchestration_service.create_job(job_data)
        assert job.status == JobStatus.PENDING

        # Start the job
        job = await orchestration_service.start_job(job.id)
        assert job.status == JobStatus.RUNNING

        # Update to complete
        job = await orchestration_service.update_job(
            job_id=job.id, job_data=JobUpdate(status=JobStatus.COMPLETED)
        )
        assert job.status == JobStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_job_failure_transition(self, job_repository, test_job):
        """Test transitioning a job to a failed state."""
        # Update to RUNNING
        job = await job_repository.update_job(
            job_id=test_job.id,
            status=JobStatus.RUNNING,
        )
        assert job.status == JobStatus.RUNNING

        # Update to FAILED
        job = await job_repository.update_job(
            job_id=job.id,
            status=JobStatus.FAILED,
        )
        assert job.status == JobStatus.FAILED


class TestTaskStateTransitions:
    """Tests for task state transitions."""

    @pytest.mark.asyncio
    async def test_task_lifecycle_transitions(self, task_repository, test_task):
        """Test a full task lifecycle with state transitions."""
        task_id = test_task.id

        # Initial state should be PENDING
        task = await task_repository.get_task(task_id)
        assert task.status == TaskStatus.PENDING

        # Update to RUNNING
        task = await task_repository.update_task(
            task_id=task_id,
            status=TaskStatus.RUNNING,
        )
        assert task.status == TaskStatus.RUNNING

        # Update to COMPLETED
        task = await task_repository.update_task(
            task_id=task_id,
            status=TaskStatus.COMPLETED,
        )
        assert task.status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_task_failure_transition(self, task_repository, test_task):
        """Test transitioning a task to a failed state."""
        # Update to RUNNING
        task = await task_repository.update_task(
            task_id=test_task.id,
            status=TaskStatus.RUNNING,
        )
        assert task.status == TaskStatus.RUNNING

        # Update to FAILED
        task = await task_repository.update_task(
            task_id=task.id,
            status=TaskStatus.FAILED,
        )
        assert task.status == TaskStatus.FAILED


class TestStatePersistence:
    """Tests for state persistence in the orchestration engine."""

    @pytest.mark.asyncio
    async def test_job_state_persistence(self, job_repository, test_job):
        """Test that job state changes are persisted to the database."""
        job_id = test_job.id

        # Update state
        await job_repository.update_job(
            job_id=job_id,
            status=JobStatus.RUNNING,
        )

        # Retrieve fresh from repository to ensure it was persisted
        job = await job_repository.get_job(job_id)
        assert job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_task_state_persistence(self, task_repository, test_task):
        """Test that task state changes are persisted to the database."""
        task_id = test_task.id

        # Update state
        await task_repository.update_task(
            task_id=task_id,
            status=TaskStatus.RUNNING,
        )

        # Retrieve fresh from repository to ensure it was persisted
        task = await task_repository.get_task(task_id)
        assert task.status == TaskStatus.RUNNING

    @pytest.mark.asyncio
    async def test_job_state_recovery(self, job_repository, test_job):
        """Test recovery of job state after 'system restart'."""
        job_id = test_job.id

        # Update state
        await job_repository.update_job(
            job_id=job_id,
            status=JobStatus.RUNNING,
        )

        # Create a new repository instance to simulate restart
        new_repository = MockJobRepository(job_repository.session)

        # Retrieve job from new repository
        job = await new_repository.get_job(job_id)
        assert job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_complex_state_with_tasks(self, orchestration_service):
        """Test complex state with job and multiple tasks."""
        # Create a job
        job_data = JobCreate(
            name="Complex State Job",
            job_type=JobType.SCAN,
            target="complex-state.example.com",
        )
        job = await orchestration_service.create_job(job_data)

        # Add tasks
        task1_data = TaskCreate(
            job_id=job.id,
            name="Task 1",
            description="First task",
        )
        task2_data = TaskCreate(
            job_id=job.id,
            name="Task 2",
            description="Second task",
        )

        task1 = await orchestration_service.create_task(task1_data)
        task2 = await orchestration_service.create_task(task2_data)

        # Start job and tasks
        job = await orchestration_service.start_job(job.id)
        task1 = await orchestration_service.update_task(
            task_id=task1.id, task_data=TaskUpdate(status=TaskStatus.RUNNING)
        )

        # Complete first task
        task1 = await orchestration_service.update_task(
            task_id=task1.id,
            task_data=TaskUpdate(status=TaskStatus.COMPLETED, result={"success": True}),
        )

        # Start and fail second task
        task2 = await orchestration_service.update_task(
            task_id=task2.id, task_data=TaskUpdate(status=TaskStatus.RUNNING)
        )
        task2 = await orchestration_service.update_task(
            task_id=task2.id,
            task_data=TaskUpdate(
                status=TaskStatus.FAILED, result={"error": "Test error"}
            ),
        )

        # Fail the job
        job = await orchestration_service.update_job(
            job_id=job.id, job_data=JobUpdate(status=JobStatus.FAILED)
        )

        # Verify final state
        retrieved_job = await orchestration_service.get_job(job.id)
        assert retrieved_job.status == JobStatus.FAILED

        tasks = await orchestration_service.get_tasks_by_job(job.id)
        assert len(tasks) == 2

        task_statuses = {task.name: task.status for task in tasks}
        assert task_statuses["Task 1"] == TaskStatus.COMPLETED
        assert task_statuses["Task 2"] == TaskStatus.FAILED


@pytest.mark.asyncio
class TestJobStatusSynchronization:
    """Tests for job status synchronization based on task statuses."""

    async def test_update_job_status_based_on_tasks(self, mock_session):
        """Test that job status is updated correctly based on task statuses."""
        # Arrange
        job_repo = MockJobRepository(mock_session)
        task_repo = MockTaskRepository(mock_session)
        orchestration_service = OrchestrationService(mock_session)

        # Mock the repositories in the service
        orchestration_service.job_repository = job_repo
        orchestration_service.task_repository = task_repo

        # Create a job
        job = await job_repo.create_job(
            name="Job Status Sync Test",
            job_type=JobType.SCAN,
            target="sync-test.example.com",
        )

        # Create tasks with different statuses
        task1 = await task_repo.create_task(
            job_id=job.id,
            name="Task 1",
            description="First task",
        )

        task2 = await task_repo.create_task(
            job_id=job.id,
            name="Task 2",
            description="Second task",
        )

        task3 = await task_repo.create_task(
            job_id=job.id,
            name="Task 3",
            description="Third task",
        )

        # Act & Assert - All tasks pending, job should remain pending
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.PENDING

        # Update one task to running
        await task_repo.update_task(
            task_id=task1.id,
            status=TaskStatus.RUNNING,
        )

        # Job should now be running
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.RUNNING

        # Complete all tasks
        await task_repo.update_task(
            task_id=task1.id,
            status=TaskStatus.COMPLETED,
        )
        await task_repo.update_task(
            task_id=task2.id,
            status=TaskStatus.COMPLETED,
        )
        await task_repo.update_task(
            task_id=task3.id,
            status=TaskStatus.COMPLETED,
        )

        # Job should now be completed
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.COMPLETED

        # Test with a failed task
        await task_repo.update_task(
            task_id=task2.id,
            status=TaskStatus.FAILED,
        )

        # Job should now be failed
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.FAILED

        # Test with all tasks cancelled
        await task_repo.update_task(
            task_id=task1.id,
            status=TaskStatus.CANCELLED,
        )
        await task_repo.update_task(
            task_id=task2.id,
            status=TaskStatus.CANCELLED,
        )
        await task_repo.update_task(
            task_id=task3.id,
            status=TaskStatus.CANCELLED,
        )

        # Job should now be cancelled
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.CANCELLED

    async def test_job_status_sync_with_mixed_task_statuses(self, mock_session):
        """Test job status synchronization with mixed task statuses."""
        # Arrange
        job_repo = MockJobRepository(mock_session)
        task_repo = MockTaskRepository(mock_session)
        orchestration_service = OrchestrationService(mock_session)

        # Mock the repositories in the service
        orchestration_service.job_repository = job_repo
        orchestration_service.task_repository = task_repo

        # Create a job
        job = await job_repo.create_job(
            name="Mixed Status Test",
            job_type=JobType.SCAN,
            target="mixed-status.example.com",
        )

        # Create tasks with different statuses
        task1 = await task_repo.create_task(
            job_id=job.id,
            name="Task 1",
            description="First task",
        )

        task2 = await task_repo.create_task(
            job_id=job.id,
            name="Task 2",
            description="Second task",
        )

        task3 = await task_repo.create_task(
            job_id=job.id,
            name="Task 3",
            description="Third task",
        )

        # Set mixed statuses
        await task_repo.update_task(
            task_id=task1.id,
            status=TaskStatus.COMPLETED,
        )
        await task_repo.update_task(
            task_id=task2.id,
            status=TaskStatus.RUNNING,
        )
        await task_repo.update_task(
            task_id=task3.id,
            status=TaskStatus.PENDING,
        )

        # Job should be running (running tasks take precedence over pending)
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.RUNNING

        # Change to completed and failed mix
        await task_repo.update_task(
            task_id=task2.id,
            status=TaskStatus.COMPLETED,
        )
        await task_repo.update_task(
            task_id=task3.id,
            status=TaskStatus.FAILED,
        )

        # Job should be failed (failed tasks take highest precedence)
        updated_job = await orchestration_service.update_job_status_based_on_tasks(
            job.id
        )
        assert updated_job.status == JobStatus.FAILED
