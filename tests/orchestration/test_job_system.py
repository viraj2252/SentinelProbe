"""Tests for job creation, queuing, and execution in the orchestration engine."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.orchestration.models import (
    Job,
    JobCreate,
    JobResponse,
    JobStatus,
    JobType,
    JobUpdate,
)
from sentinelprobe.orchestration.repository import JobRepository
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


class TestJobCreation:
    """Tests for job creation functionality."""

    @pytest.mark.asyncio
    async def test_create_job(self, job_repository):
        """Test that a job can be created with the repository."""
        # Arrange
        name = "Test Job"
        job_type = JobType.SCAN
        target = "example.com"
        description = "Test job description"
        config = {"timeout": 30, "depth": 2}

        # Act
        job = await job_repository.create_job(
            name=name,
            job_type=job_type,
            target=target,
            description=description,
            config=config,
        )

        # Assert
        assert job is not None
        assert job.id is not None
        assert job.name == name
        assert job.job_type == job_type
        assert job.target == target
        assert job.description == description
        assert job.status == JobStatus.PENDING
        assert job.created_at is not None
        assert job.updated_at is not None

    @pytest.mark.asyncio
    async def test_create_job_service(self, orchestration_service):
        """Test that a job can be created through the service layer."""
        # Arrange
        job_data = JobCreate(
            name="Test Service Job",
            job_type=JobType.SCAN,
            target="service.example.com",
            description="Test service job",
            config={"timeout": 60, "depth": 3},
        )

        # Act
        response = await orchestration_service.create_job(job_data)

        # Assert
        assert isinstance(response, JobResponse)
        assert response.id is not None
        assert response.name == job_data.name
        assert response.job_type == job_data.job_type
        assert response.target == job_data.target
        assert response.description == job_data.description
        assert response.status == JobStatus.PENDING
        assert response.created_at is not None
        assert response.updated_at is not None


class TestJobQueuing:
    """Tests for job queuing functionality."""

    @pytest.mark.asyncio
    async def test_get_pending_jobs(self, job_repository, mock_session):
        """Test retrieving pending jobs."""
        # Arrange - manually create and add jobs to the mock session
        job1 = Job(
            name="Pending Job 1",
            job_type=JobType.SCAN,
            target="pending1.example.com",
            status=JobStatus.PENDING,
        )
        job2 = Job(
            name="Pending Job 2",
            job_type=JobType.SCAN,
            target="pending2.example.com",
            status=JobStatus.PENDING,
        )
        job3 = Job(
            name="Running Job",
            job_type=JobType.SCAN,
            target="running.example.com",
            status=JobStatus.RUNNING,
        )

        mock_session.add(job1)
        mock_session.add(job2)
        mock_session.add(job3)

        # Act
        pending_jobs = await job_repository.get_jobs(status=JobStatus.PENDING)

        # Assert
        assert len(pending_jobs) == 2
        for job in pending_jobs:
            assert job.status == JobStatus.PENDING

    @pytest.mark.asyncio
    async def test_get_pending_jobs_service(self, orchestration_service):
        """Test retrieving pending jobs through service layer."""
        # Arrange
        job1 = JobCreate(
            name="Service Pending Job 1",
            job_type=JobType.SCAN,
            target="service-pending1.example.com",
        )
        job2 = JobCreate(
            name="Service Pending Job 2",
            job_type=JobType.SCAN,
            target="service-pending2.example.com",
        )

        await orchestration_service.create_job(job1)
        await orchestration_service.create_job(job2)

        # Act
        pending_jobs = await orchestration_service.get_jobs(status=JobStatus.PENDING)

        # Assert
        assert len(pending_jobs) == 2
        for job in pending_jobs:
            assert job.status == JobStatus.PENDING


class TestJobExecution:
    """Tests for job execution functionality."""

    @pytest.mark.asyncio
    async def test_start_job(self, job_repository):
        """Test starting a job changes its status."""
        # Arrange
        job = await job_repository.create_job(
            name="Job to Start",
            job_type=JobType.SCAN,
            target="start.example.com",
        )
        assert job.status == JobStatus.PENDING

        # Act
        updated_job = await job_repository.update_job(
            job_id=job.id,
            status=JobStatus.RUNNING,
        )

        # Assert
        assert updated_job is not None
        assert updated_job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_start_job_service(self, orchestration_service):
        """Test starting a job through service layer."""
        # Arrange
        job_data = JobCreate(
            name="Service Job to Start",
            job_type=JobType.SCAN,
            target="service-start.example.com",
        )
        job_response = await orchestration_service.create_job(job_data)
        assert job_response.status == JobStatus.PENDING

        # Act
        started_job = await orchestration_service.start_job(job_response.id)

        # Assert
        assert started_job is not None
        assert started_job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_complete_job(self, job_repository, mock_session):
        """Test completing a job changes its status."""
        # Arrange - manually create a job in RUNNING state
        job = Job(
            name="Job to Complete",
            job_type=JobType.SCAN,
            target="complete.example.com",
            status=JobStatus.RUNNING,
        )
        mock_session.add(job)

        # Act
        updated_job = await job_repository.update_job(
            job_id=job.id,
            status=JobStatus.COMPLETED,
        )

        # Assert
        assert updated_job is not None
        assert updated_job.status == JobStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_cancel_job(self, orchestration_service):
        """Test cancelling a job through service layer."""
        # Arrange
        job_data = JobCreate(
            name="Job to Cancel",
            job_type=JobType.SCAN,
            target="cancel.example.com",
        )
        job_response = await orchestration_service.create_job(job_data)
        started_job = await orchestration_service.start_job(job_response.id)
        assert started_job.status == JobStatus.RUNNING

        # Act
        cancelled_job = await orchestration_service.cancel_job(job_response.id)

        # Assert
        assert cancelled_job is not None
        assert cancelled_job.status == JobStatus.CANCELLED
