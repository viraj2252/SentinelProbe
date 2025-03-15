"""Test fixtures for the reporting package."""

import asyncio
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from sentinelprobe.core.db import Base
from sentinelprobe.reporting.models import Report


@pytest.fixture(autouse=True)
def mock_mongodb():
    """Mock MongoDB connection for testing."""
    # Create a mock collection with the necessary methods
    mock_collection = AsyncMock()
    mock_collection.delete_one.return_value = AsyncMock()
    mock_collection.insert_one.return_value = AsyncMock(inserted_id="test_id")
    mock_collection.find_one.return_value = {"report_id": 1, "data": {"test": "data"}}

    # Patch the connect_to_mongo function to do nothing
    with patch(
        "sentinelprobe.core.mongodb.connect_to_mongo", return_value=None
    ) as mock_connect:
        # Also patch get_collection to return our mock
        with patch(
            "sentinelprobe.core.mongodb.get_collection", return_value=mock_collection
        ):
            # Make connect_to_mongo an async function that returns immediately
            mock_connect.side_effect = AsyncMock(return_value=None)
            yield mock_collection


@pytest_asyncio.fixture
async def test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    # Create an in-memory database for testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Create only the tables needed for reporting tests
    async with engine.begin() as conn:
        # Create a temporary metadata with only the tables we need
        from sqlalchemy import MetaData

        metadata = MetaData()
        # Import the Job model since Report has a foreign key to it
        from sentinelprobe.orchestration.models import Job

        # Copy the table definitions we need
        for table in [Report.__table__, Job.__table__]:
            table.to_metadata(metadata)

        # Create only these tables
        await conn.run_sync(metadata.create_all)

    # Create session
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Yield a session
    async with async_session() as session:
        yield session

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
