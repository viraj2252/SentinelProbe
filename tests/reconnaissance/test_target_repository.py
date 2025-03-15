"""Tests for the Target repository."""

import pytest
import pytest_asyncio

from sentinelprobe.reconnaissance.models import TargetStatus
from tests.reconnaissance.mock_repository import MockTargetRepository
from tests.reconnaissance.mock_session import MockSession


class TestTargetRepository:
    """Tests for the Target repository."""

    @pytest_asyncio.fixture
    async def session(self):
        """Create a mock session."""
        return MockSession()

    @pytest_asyncio.fixture
    async def target_repository(self, session):
        """Create a target repository."""
        return MockTargetRepository(session)

    @pytest.mark.asyncio
    async def test_create_target(self, target_repository):
        """Test creating a target."""
        # Arrange
        job_id = 1
        hostname = "example.com"
        ip_address = "192.0.2.1"
        metadata = {"source": "test"}

        # Act
        target = await target_repository.create_target(
            job_id=job_id,
            hostname=hostname,
            ip_address=ip_address,
            metadata=metadata,
        )

        # Assert
        assert target is not None
        assert target.id is not None
        assert target.job_id == job_id
        assert target.hostname == hostname
        assert target.ip_address == ip_address
        assert target.status == TargetStatus.PENDING
        assert target.target_metadata == metadata
        assert target.created_at is not None
        assert target.started_at is None
        assert target.completed_at is None

    @pytest.mark.asyncio
    async def test_get_target(self, target_repository):
        """Test getting a target."""
        # Arrange
        target = await target_repository.create_target(
            job_id=1,
            hostname="example.com",
        )

        # Act
        retrieved_target = await target_repository.get_target(target.id)

        # Assert
        assert retrieved_target is not None
        assert retrieved_target.id == target.id
        assert retrieved_target.hostname == "example.com"

    @pytest.mark.asyncio
    async def test_get_targets_by_job(self, target_repository):
        """Test getting targets by job."""
        # Arrange
        job_id = 1
        await target_repository.create_target(job_id=job_id, hostname="test1.com")
        await target_repository.create_target(job_id=job_id, hostname="test2.com")
        await target_repository.create_target(job_id=2, hostname="other.com")

        # Act
        targets = await target_repository.get_targets_by_job(job_id)

        # Assert
        assert len(targets) == 2
        hostnames = [target.hostname for target in targets]
        assert "test1.com" in hostnames
        assert "test2.com" in hostnames
        assert "other.com" not in hostnames

    @pytest.mark.asyncio
    async def test_update_target(self, target_repository):
        """Test updating a target."""
        # Arrange
        target = await target_repository.create_target(
            job_id=1,
            hostname="example.com",
        )

        # Act
        updated_target = await target_repository.update_target(
            target_id=target.id,
            hostname="updated.com",
            ip_address="192.0.2.2",
            status=TargetStatus.SCANNING,
        )

        # Assert
        assert updated_target is not None
        assert updated_target.hostname == "updated.com"
        assert updated_target.ip_address == "192.0.2.2"
        assert updated_target.status == TargetStatus.SCANNING
        assert updated_target.started_at is not None

    @pytest.mark.asyncio
    async def test_delete_target(self, target_repository):
        """Test deleting a target."""
        # Arrange
        target = await target_repository.create_target(
            job_id=1,
            hostname="example.com",
        )

        # Act
        result = await target_repository.delete_target(target.id)
        deleted_target = await target_repository.get_target(target.id)

        # Assert
        assert result is True
        assert deleted_target is None
