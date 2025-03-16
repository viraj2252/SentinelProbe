"""API interface for the Orchestration module."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.db import get_db_session
from sentinelprobe.core.logging import get_logger
from sentinelprobe.orchestration.models import (
    JobCreate,
    JobResponse,
    JobStatus,
    JobUpdate,
    TaskCreate,
    TaskResponse,
)
from sentinelprobe.orchestration.service import OrchestrationService

logger = get_logger(__name__)

router = APIRouter(prefix="/orchestration", tags=["orchestration"])


@router.post(
    "/jobs",
    response_model=JobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Job",
)
async def create_job(
    job_data: JobCreate, session: AsyncSession = Depends(get_db_session)
) -> JobResponse:
    """
    Create a new job.

    Args:
        job_data: Job creation data
        session: Database session

    Returns:
        Created job
    """
    service = OrchestrationService(session)
    try:
        return await service.create_job(job_data)
    except Exception as e:
        logger.error(f"Error creating job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating job: {str(e)}",
        )


@router.get(
    "/jobs",
    response_model=List[JobResponse],
    summary="List Jobs",
)
async def list_jobs(
    limit: int = Query(100, description="Maximum number of jobs to return"),
    offset: int = Query(0, description="Number of jobs to skip"),
    status_filter: Optional[JobStatus] = Query(
        None, description="Filter by status", alias="status"
    ),
    session: AsyncSession = Depends(get_db_session),
) -> List[JobResponse]:
    """
    List jobs with optional filtering.

    Args:
        limit: Maximum number of jobs to return
        offset: Number of jobs to skip
        status_filter: Filter by status (optional)
        session: Database session

    Returns:
        List of jobs
    """
    service = OrchestrationService(session)
    try:
        return await service.get_jobs(limit, offset, status_filter)
    except Exception as e:
        logger.error(f"Error listing jobs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing jobs: {str(e)}",
        )


@router.get(
    "/jobs/{job_id}",
    response_model=JobResponse,
    summary="Get Job",
)
async def get_job(
    job_id: int = Path(..., description="Job ID"),
    session: AsyncSession = Depends(get_db_session),
) -> JobResponse:
    """
    Get job details.

    Args:
        job_id: Job ID
        session: Database session

    Returns:
        Job details
    """
    service = OrchestrationService(session)
    try:
        job = await service.get_job(job_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job with ID {job_id} not found",
            )
        return job
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting job: {str(e)}",
        )


@router.patch(
    "/jobs/{job_id}",
    response_model=JobResponse,
    summary="Update Job",
)
async def update_job(
    job_data: JobUpdate,
    job_id: int = Path(..., description="Job ID"),
    session: AsyncSession = Depends(get_db_session),
) -> JobResponse:
    """
    Update job details.

    Args:
        job_data: Job update data
        job_id: Job ID
        session: Database session

    Returns:
        Updated job
    """
    service = OrchestrationService(session)
    try:
        job = await service.update_job(job_id, job_data)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job with ID {job_id} not found",
            )
        return job
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating job: {str(e)}",
        )


@router.delete(
    "/jobs/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Job",
)
async def delete_job(
    job_id: int = Path(..., description="Job ID"),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """
    Delete a job.

    Args:
        job_id: Job ID
        session: Database session
    """
    service = OrchestrationService(session)
    try:
        deleted = await service.delete_job(job_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job with ID {job_id} not found",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting job: {str(e)}",
        )


@router.post(
    "/tasks",
    response_model=TaskResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Task",
)
async def create_task(
    task_data: TaskCreate, session: AsyncSession = Depends(get_db_session)
) -> TaskResponse:
    """
    Create a new task.

    Args:
        task_data: Task creation data
        session: Database session

    Returns:
        Created task
    """
    service = OrchestrationService(session)
    try:
        task = await service.create_task(task_data)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job with ID {task_data.job_id} not found",
            )
        return task
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating task: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating task: {str(e)}",
        )
