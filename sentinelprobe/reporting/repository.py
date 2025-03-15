"""Repository layer for the Reporting Engine."""

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.db import get_db_session
from sentinelprobe.core.mongodb import get_collection
from sentinelprobe.reporting.models import (
    Report,
    ReportData,
    ReportFormat,
    ReportStatus,
    ReportType,
)


class ReportRepository:
    """Repository for report management."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize report repository."""
        self.session = session
        self.reports_dir = Path(get_settings().REPORT_DIR)
        self._ensure_report_dir()

    def _ensure_report_dir(self) -> None:
        """Ensure reports directory exists."""
        os.makedirs(self.reports_dir, exist_ok=True)

    async def get_session(self) -> AsyncSession:
        """Get database session, creating one if none exists."""
        if self.session is None:
            session_gen = get_db_session()
            self.session = await session_gen.__anext__()
        return cast(AsyncSession, self.session)

    async def create_report(
        self,
        job_id: int,
        report_type: ReportType,
        report_format: ReportFormat,
        title: str,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Report:
        """
        Create a new report record.

        Args:
            job_id: ID of the job associated with this report
            report_type: Type of report to generate
            report_format: Format of the report output
            title: Report title
            description: Report description
            metadata: Additional metadata

        Returns:
            Created report instance
        """
        session = await self.get_session()

        report = Report(
            job_id=job_id,
            report_type=report_type,
            report_format=report_format,
            status=ReportStatus.PENDING,
            title=title,
            description=description,
            report_metadata=metadata or {},
        )

        session.add(report)
        await session.commit()
        await session.refresh(report)
        return report

    async def get_report(self, report_id: int) -> Optional[Report]:
        """
        Retrieve a report by ID.

        Args:
            report_id: ID of the report

        Returns:
            Report if found, otherwise None
        """
        session = await self.get_session()
        result = await session.execute(select(Report).where(Report.id == report_id))
        return cast(Optional[Report], result.scalars().first())

    async def update_report_status(
        self, report_id: int, status: ReportStatus
    ) -> Optional[Report]:
        """
        Update a report's status.

        Args:
            report_id: ID of the report
            status: New report status

        Returns:
            Updated report or None if not found
        """
        session = await self.get_session()
        report = await self.get_report(report_id)

        if report:
            report.status = status
            report.updated_at = datetime.utcnow()
            await session.commit()
            await session.refresh(report)

        return report

    async def update_report_content_path(
        self, report_id: int, content_path: str
    ) -> Optional[Report]:
        """
        Update a report's content path.

        Args:
            report_id: ID of the report
            content_path: Path to the report content file

        Returns:
            Updated report or None if not found
        """
        session = await self.get_session()
        report = await self.get_report(report_id)

        if report:
            report.content_path = content_path
            report.updated_at = datetime.utcnow()
            await session.commit()
            await session.refresh(report)

        return report

    async def get_reports_by_job(self, job_id: int) -> List[Report]:
        """
        Get all reports associated with a job.

        Args:
            job_id: ID of the job

        Returns:
            List of reports for the job
        """
        session = await self.get_session()
        result = await session.execute(select(Report).where(Report.job_id == job_id))
        return list(result.scalars().all())

    async def store_report_data(self, report_data: ReportData) -> str:
        """
        Store detailed report data in MongoDB.

        Args:
            report_data: Report data to store

        Returns:
            MongoDB document ID
        """
        collection = await get_collection("report_data")
        result = await collection.insert_one(report_data.dict())
        return str(result.inserted_id)

    async def get_report_data(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve report data from MongoDB.

        Args:
            report_id: ID of the report

        Returns:
            Report data if found, otherwise None
        """
        collection = await get_collection("report_data")
        result = await collection.find_one({"report_id": report_id})
        return cast(Optional[Dict[str, Any]], result)

    async def save_report_file(
        self, report_id: int, content: str, report_format: ReportFormat
    ) -> str:
        """
        Save report content to a file.

        Args:
            report_id: ID of the report
            content: Report content
            report_format: Format of the report

        Returns:
            Path to the saved file
        """
        # Create a filename based on report ID and format
        file_extension = report_format.value.lower()
        filename = f"report_{report_id}.{file_extension}"
        file_path = self.reports_dir / filename

        # Write the content to the file
        with open(file_path, "w") as f:
            f.write(content)

        # Update the report record with the file path
        relative_path = str(file_path.relative_to(Path.cwd()))
        await self.update_report_content_path(report_id, relative_path)

        return str(file_path)

    async def delete_report(self, report_id: int) -> bool:
        """
        Delete a report and its associated file.

        Args:
            report_id: ID of the report

        Returns:
            True if successfully deleted, False otherwise
        """
        session = await self.get_session()
        report = await self.get_report(report_id)

        if not report:
            return False

        # Delete any associated file
        if report.content_path:
            try:
                os.remove(report.content_path)
            except (FileNotFoundError, PermissionError):
                # Log error but continue with DB deletion
                pass

        # Delete MongoDB data if it exists
        collection = await get_collection("report_data")
        await collection.delete_one({"report_id": report_id})

        # Delete from SQL database
        await session.delete(report)
        await session.commit()

        return True
