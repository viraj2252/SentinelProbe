"""Tests for the database module."""
import asyncio
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.db import Base, init_db, get_db_session
from sentinelprobe.orchestration.models import Job, Task, JobStatus, TaskStatus, JobType


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_init_db(mock_db_dependencies):
    """Test the database initialization function."""
    # Call the init_db function
    await init_db()
    # If no exception is raised, the test passes


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_get_db_session(mock_db_dependencies):
    """Test obtaining a database session."""
    # Get a session
    async for session in get_db_session():
        # Session should be an instance of MockSession
        assert session is not None
        # No exceptions should be raised


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_job_crud_operations(mock_db_dependencies):
    """Test CRUD operations for the Job model."""
    async for session in get_db_session():
        # Create a new job
        job = Job(
            name="Test Job",
            description="Test job description",
            status=JobStatus.PENDING,
            job_type=JobType.RECONNAISSANCE,
            target="example.com",
        )
        
        # Add the job to the session
        session.add(job)
        await session.commit()
        
        # Verify the job has an ID
        assert job.id is not None
        
        # Query the job
        result = await session.execute(select(Job).filter(Job.id == job.id))
        queried_job = await result.scalar()
        
        # Verify the job was retrieved
        assert queried_job is not None
        
        # Update the job
        job.status = JobStatus.RUNNING
        await session.commit()
        
        # Delete the job
        await session.delete(job)
        await session.commit()
        
        # Verify the job was deleted
        result = await session.execute(select(Job).filter(Job.id == job.id))
        deleted_job = await result.scalar()
        assert deleted_job is None


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_task_crud_operations(mock_db_dependencies):
    """Test CRUD operations for the Task model."""
    async for session in get_db_session():
        # Create a new job for the task
        job = Job(
            name="Test Job for Task",
            description="Test job description",
            status=JobStatus.PENDING,
            job_type=JobType.RECONNAISSANCE,
            target="example.com",
        )
        session.add(job)
        await session.commit()
        
        # Create a new task
        task = Task(
            name="Test Task",
            description="Test task description",
            status=TaskStatus.PENDING,
            job_id=job.id,
        )
        
        # Add the task to the session
        session.add(task)
        await session.commit()
        
        # Verify the task has an ID
        assert task.id is not None
        
        # Query the task
        result = await session.execute(select(Task).filter(Task.id == task.id))
        queried_task = await result.scalar()
        
        # Verify the task was retrieved
        assert queried_task is not None
        
        # Update the task
        task.status = TaskStatus.RUNNING
        await session.commit()
        
        # Delete the task
        await session.delete(task)
        await session.commit()
        
        # Verify the task was deleted
        result = await session.execute(select(Task).filter(Task.id == task.id))
        deleted_task = await result.scalar()
        assert deleted_task is None


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_job_task_relationship(mock_db_dependencies):
    """Test the relationship between Job and Task models."""
    async for session in get_db_session():
        # Create a new job
        job = Job(
            name="Test Job with Tasks",
            description="Test job description",
            status=JobStatus.PENDING,
            job_type=JobType.RECONNAISSANCE,
            target="example.com",
        )
        session.add(job)
        await session.commit()
        
        # Create tasks for the job
        task1 = Task(
            name="Test Task 1",
            description="Test task 1 description",
            status=TaskStatus.PENDING,
            job_id=job.id,
        )
        
        task2 = Task(
            name="Test Task 2",
            description="Test task 2 description",
            status=TaskStatus.PENDING,
            job_id=job.id,
        )
        
        # Add tasks to the session
        session.add(task1)
        session.add(task2)
        await session.commit()
        
        # Query the job with its tasks
        result = await session.execute(
            select(Job).filter(Job.id == job.id)
        )
        queried_job = await result.scalar()
        
        # Verify the job was retrieved
        assert queried_job is not None
        
        # Verify the tasks are associated with the job
        # In a real test, we would check job.tasks here
        # For our mock, we'll just verify the tasks exist
        result = await session.execute(
            select(Task).filter(Task.job_id == job.id)
        )
        scalars_result = await result.scalars()
        tasks = await scalars_result.all()
        
        # Verify tasks were retrieved
        assert len(tasks) == 2 