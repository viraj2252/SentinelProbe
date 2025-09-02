"""API endpoints for the Reporting Engine."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.db import get_db_session
from sentinelprobe.reporting.models import ReportRequest
from sentinelprobe.reporting.service import ReportingService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/", status_code=201)
async def create_report(
    request: ReportRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Create a new report.

    Args:
        request: Report generation request
        session: Database session

    Returns:
        Report ID
    """
    service = ReportingService(session)
    report_id = await service.create_report(request)
    return {"report_id": report_id}


@router.post("/{report_id}/generate", status_code=202)
async def generate_report(
    report_id: int = Path(..., description="Report ID"),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Generate a report.

    Args:
        report_id: Report ID
        session: Database session

    Returns:
        Status message
    """
    service = ReportingService(session)
    try:
        file_path = await service.generate_report(report_id)
        return {"status": "success", "file_path": file_path}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to generate report: {str(e)}"
        )


@router.get("/{report_id}")
async def get_report_status(
    report_id: int = Path(..., description="Report ID"),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Get report status.

    Args:
        report_id: Report ID
        session: Database session

    Returns:
        Report status
    """
    service = ReportingService(session)
    report = await service.report_repository.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404, detail=f"Report with ID {report_id} not found"
        )

    result = {
        "id": report.id,
        "job_id": report.job_id,
        "title": report.title,
        "description": report.description,
        "report_type": report.report_type.value,
        "report_format": report.report_format.value,
        "status": report.status.value,
        "created_at": report.created_at.isoformat(),
        "updated_at": report.updated_at.isoformat(),
    }

    if report.content_path:
        result["content_path"] = report.content_path

    return result


@router.get("/job/{job_id}")
async def get_reports_by_job(
    job_id: int = Path(..., description="Job ID"),
    session: AsyncSession = Depends(get_db_session),
) -> List[dict]:
    """
    Get reports by job ID.

    Args:
        job_id: Job ID
        session: Database session

    Returns:
        List of reports
    """
    service = ReportingService(session)
    reports = await service.report_repository.get_reports_by_job(job_id)

    return [
        {
            "id": report.id,
            "job_id": report.job_id,
            "title": report.title,
            "report_type": report.report_type.value,
            "report_format": report.report_format.value,
            "status": report.status.value,
            "created_at": report.created_at.isoformat(),
        }
        for report in reports
    ]


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: int = Path(..., description="Report ID"),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """
    Delete a report.

    Args:
        report_id: Report ID
        session: Database session
    """
    service = ReportingService(session)
    success = await service.delete_report(report_id)
    if not success:
        raise HTTPException(
            status_code=404, detail=f"Report with ID {report_id} not found"
        )
