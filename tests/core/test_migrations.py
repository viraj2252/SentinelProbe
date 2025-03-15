"""Tests for the migrations module."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from sentinelprobe.core.migrations import (
    get_tables,
    table_exists,
    create_schema,
    drop_schema,
    recreate_schema,
    run_migration
)
from sentinelprobe.orchestration.models import Job, Task


class AsyncContextManagerMock:
    """A mock that can be used as an async context manager."""
    
    def __init__(self, return_value):
        self.return_value = return_value
        
    async def __aenter__(self):
        return self.return_value
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_get_tables():
    """Test retrieving table names from the database."""
    # Create a mock engine
    mock_engine = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock(return_value=["job", "task"])
    
    # Set up the mock connection with a proper async context manager
    mock_engine.connect = MagicMock(return_value=AsyncContextManagerMock(mock_conn))
    
    # Call the function with our mock engine
    tables = await get_tables(mock_engine)
    
    # Verify results
    assert isinstance(tables, list)
    assert "job" in tables
    assert "task" in tables


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_table_exists():
    """Test checking if a table exists."""
    # Patch get_tables to return a known list
    with patch("sentinelprobe.core.migrations.get_tables", AsyncMock(return_value=["job", "task"])):
        # Call the function with a dummy engine (it will be ignored due to the patch)
        exists = await table_exists(MagicMock(), "job")
        not_exists = await table_exists(MagicMock(), "nonexistent_table")
        
        # Verify results
        assert exists is True
        assert not_exists is False


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_create_schema():
    """Test creating the database schema."""
    # Create a mock engine
    mock_engine = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock()
    
    # Set up the mock connection for begin with a proper async context manager
    mock_engine.begin = MagicMock(return_value=AsyncContextManagerMock(mock_conn))
    
    # Patch get_tables to return different values on each call
    with patch("sentinelprobe.core.migrations.get_tables", AsyncMock(side_effect=[[], ["job", "task"]])):
        # Call the function with our mock engine
        created_tables = await create_schema(mock_engine)
        
        # Verify results
        assert isinstance(created_tables, list)
        assert len(created_tables) == 2
        assert "job" in created_tables
        assert "task" in created_tables


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_drop_schema():
    """Test dropping the database schema."""
    # Create a mock engine
    mock_engine = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock()
    
    # Set up the mock connection for begin with a proper async context manager
    mock_engine.begin = MagicMock(return_value=AsyncContextManagerMock(mock_conn))
    
    # Patch get_tables to return different values on each call
    with patch("sentinelprobe.core.migrations.get_tables", AsyncMock(side_effect=[["job", "task"], []])):
        # Call the function with our mock engine
        dropped_tables = await drop_schema(mock_engine)
        
        # Verify results
        assert isinstance(dropped_tables, list)
        assert len(dropped_tables) == 2
        assert "job" in dropped_tables
        assert "task" in dropped_tables


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_recreate_schema():
    """Test recreating the database schema."""
    # Mock drop_schema and create_schema
    with patch("sentinelprobe.core.migrations.drop_schema", AsyncMock(return_value=["job", "task"])), \
         patch("sentinelprobe.core.migrations.create_schema", AsyncMock(return_value=["job", "task"])):
        
        # Call the function with a dummy engine (it will be ignored due to the patches)
        dropped, created = await recreate_schema(MagicMock())
        
        # Verify results
        assert isinstance(dropped, list)
        assert isinstance(created, list)
        assert len(dropped) == 2
        assert len(created) == 2
        assert "job" in dropped
        assert "task" in created


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_run_migration():
    """Test running a migration."""
    # Mock create_schema
    with patch("sentinelprobe.core.migrations.create_schema", AsyncMock(return_value=["job", "task"])):
        
        # Call the function with no migration name (should call create_schema)
        result = await run_migration(None, MagicMock())
        
        # Verify results
        assert isinstance(result, list)
        assert len(result) == 2
        assert "job" in result
        assert "task" in result


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_table_columns():
    """Test that tables have the expected columns."""
    # Define expected columns
    job_columns = ["id", "name", "description", "job_type", "status", "target", "created_at", "updated_at"]
    task_columns = ["id", "name", "description", "status", "job_id", "created_at", "updated_at"]
    
    # Verify Job model columns
    for column in job_columns:
        assert hasattr(Job, column), f"Job model missing column: {column}"
    
    # Verify Task model columns
    for column in task_columns:
        assert hasattr(Task, column), f"Task model missing column: {column}"


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_foreign_keys():
    """Test that foreign keys are properly defined."""
    # Verify Task has a foreign key to Job
    assert hasattr(Task, "job_id"), "Task model missing job_id foreign key"
    assert hasattr(Task, "job"), "Task model missing job relationship" 