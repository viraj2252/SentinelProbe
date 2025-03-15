"""Tests for the Report Repository."""

import os
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from sentinelprobe.reporting.models import (
    Report,
    ReportFormat,
    ReportStatus,
    ReportType,
)
from sentinelprobe.reporting.repository import ReportRepository


class TestReportRepository:
    """Test cases for the Report Repository."""

    @pytest.mark.asyncio
    async def test_create_report(self, test_db_session):
        """Test creating a report."""
        repo = ReportRepository(test_db_session)

        report = await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report",
            description="Test Description",
            metadata={"test": "data"},
        )

        assert report.id is not None
        assert report.job_id == 1
        assert report.report_type == ReportType.SUMMARY
        assert report.report_format == ReportFormat.JSON
        assert report.title == "Test Report"
        assert report.description == "Test Description"
        assert report.status == ReportStatus.PENDING
        assert report.report_metadata == {"test": "data"}
        assert report.created_at is not None
        assert report.updated_at is not None
        assert report.content_path is None

    @pytest.mark.asyncio
    async def test_get_report(self, test_db_session):
        """Test retrieving a report."""
        repo = ReportRepository(test_db_session)

        # Create a report
        report = await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report",
        )

        # Retrieve the report
        retrieved_report = await repo.get_report(report.id)

        assert retrieved_report is not None
        assert retrieved_report.id == report.id
        assert retrieved_report.job_id == report.job_id
        assert retrieved_report.report_type == report.report_type
        assert retrieved_report.report_format == report.report_format
        assert retrieved_report.title == report.title

    @pytest.mark.asyncio
    async def test_update_report_status(self, test_db_session):
        """Test updating a report's status."""
        repo = ReportRepository(test_db_session)

        # Create a report
        report = await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report",
        )

        # Update the status
        updated_report = await repo.update_report_status(
            report.id, ReportStatus.IN_PROGRESS
        )

        assert updated_report is not None
        assert updated_report.status == ReportStatus.IN_PROGRESS

        # Verify in database
        result = await test_db_session.execute(
            select(Report).where(Report.id == report.id)
        )
        db_report = result.scalar_one()
        assert db_report.status == ReportStatus.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_get_reports_by_job(self, test_db_session):
        """Test retrieving reports by job ID."""
        repo = ReportRepository(test_db_session)

        # Create reports for job 1
        await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report 1",
        )
        await repo.create_report(
            job_id=1,
            report_type=ReportType.VULNERABILITY,
            report_format=ReportFormat.HTML,
            title="Test Report 2",
        )

        # Create a report for job 2
        await repo.create_report(
            job_id=2,
            report_type=ReportType.FULL,
            report_format=ReportFormat.PDF,
            title="Test Report 3",
        )

        # Retrieve reports for job 1
        reports = await repo.get_reports_by_job(1)

        assert len(reports) == 2
        assert all(report.job_id == 1 for report in reports)
        assert any(report.title == "Test Report 1" for report in reports)
        assert any(report.title == "Test Report 2" for report in reports)

    @pytest.mark.asyncio
    async def test_save_report_file(self, test_db_session, tmp_path):
        """Test saving a report file."""
        # Use a temporary directory for testing
        test_reports_dir = tmp_path / "reports"
        os.makedirs(test_reports_dir, exist_ok=True)

        repo = ReportRepository(test_db_session)
        repo.reports_dir = test_reports_dir

        # Create a report
        report = await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report",
        )

        # Save a report file
        content = '{"test": "content"}'
        file_path = await repo.save_report_file(report.id, content, ReportFormat.JSON)

        # Verify file exists and contains the content
        assert os.path.exists(file_path)
        with open(file_path, "r") as f:
            assert f.read() == content

        # Verify the report record was updated
        updated_report = await repo.get_report(report.id)
        assert updated_report.content_path is not None

    @pytest.mark.asyncio
    async def test_delete_report(self, test_db_session, tmp_path):
        """Test deleting a report."""
        # Use a temporary directory for testing
        test_reports_dir = tmp_path / "reports"
        os.makedirs(test_reports_dir, exist_ok=True)

        repo = ReportRepository(test_db_session)
        repo.reports_dir = test_reports_dir

        # Create a report
        report = await repo.create_report(
            job_id=1,
            report_type=ReportType.SUMMARY,
            report_format=ReportFormat.JSON,
            title="Test Report",
        )

        # Save a report file
        content = '{"test": "content"}'
        file_path = await repo.save_report_file(report.id, content, ReportFormat.JSON)

        # Delete the report
        success = await repo.delete_report(report.id)

        assert success is True

        # Verify the report record was deleted
        deleted_report = await repo.get_report(report.id)
        assert deleted_report is None

        # Verify the file was deleted
        assert not os.path.exists(file_path)
