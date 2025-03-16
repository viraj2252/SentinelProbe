"""Tests for the migrations module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from sentinelprobe.core.migrations import (
    MigrationManager,
    create_schema,
    drop_schema,
    get_tables,
    recreate_schema,
    run_migration,
    table_exists,
)
from sentinelprobe.orchestration.models import Job, Task


class AsyncContextManagerMock:
    """A mock that can be used as an async context manager."""

    def __init__(self, return_value):
        """Initialize with the value to return from __aenter__."""
        self.return_value = return_value

    async def __aenter__(self):
        """Enter the async context manager and return the stored value."""
        return self.return_value

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the async context manager."""
        return None


class MockResult:
    """Mock SQLAlchemy result."""

    def __init__(self, rows):
        """Initialize with rows."""
        self.rows = rows

    def fetchall(self):
        """Return all rows."""
        return self.rows

    def scalars(self):
        """Return self to support chaining."""
        return self

    def all(self):
        """Return all rows."""
        return self.rows

    def first(self):
        """Return first row or None."""
        return self.rows[0] if self.rows else None


class MockConnection:
    """Mock SQLAlchemy connection."""

    def __init__(self):
        """Initialize with empty state."""
        self.tables_before = []
        self.tables_after = ["job", "task"]
        self.executed = []  # Track executed queries

    async def execute(self, query):
        """Mock execute query."""
        # Convert query to string and store it for later checking
        query_str = str(query)
        self.executed.append(query_str)

        if "SELECT tablename FROM pg_tables" in query_str:
            # First call: return empty list
            # Second call: return tables
            if not self.tables_before:
                result = []
                # Switch for next call
                self.tables_before = self.tables_after
            else:
                result = [(table,) for table in self.tables_before]
            return MockResult(result)
        elif "SELECT name FROM migrations" in query_str:
            return MockResult(
                self.migrations_result if hasattr(self, "migrations_result") else []
            )
        return MockResult([])


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
    with patch(
        "sentinelprobe.core.migrations.get_tables",
        AsyncMock(return_value=["job", "task"]),
    ):
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
    mock_conn = MockConnection()
    mock_conn.run_sync = AsyncMock()

    # Set up the mock connection for begin with a proper async context manager
    mock_engine.begin = MagicMock(return_value=AsyncContextManagerMock(mock_conn))

    # Mock inspector and the get_table_names method
    mock_inspector = MagicMock()
    mock_inspector.get_table_names = AsyncMock(side_effect=[[], ["job", "task"]])

    # Patch the inspect function to return our mock inspector
    with patch("sentinelprobe.core.migrations.inspect", return_value=mock_inspector):
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

    # Mock inspector and the get_table_names method
    mock_inspector = MagicMock()
    mock_inspector.get_table_names = AsyncMock(side_effect=[["job", "task"], []])

    # Patch the inspect function to return our mock inspector
    with patch("sentinelprobe.core.migrations.inspect", return_value=mock_inspector):
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
    with (
        patch(
            "sentinelprobe.core.migrations.drop_schema",
            AsyncMock(return_value=["job", "task"]),
        ),
        patch(
            "sentinelprobe.core.migrations.create_schema",
            AsyncMock(return_value=["job", "task"]),
        ),
    ):

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
    with patch(
        "sentinelprobe.core.migrations.create_schema",
        AsyncMock(return_value=["job", "task"]),
    ):

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
    job_columns = [
        "id",
        "name",
        "description",
        "job_type",
        "status",
        "target",
        "created_at",
        "updated_at",
    ]
    task_columns = [
        "id",
        "name",
        "description",
        "status",
        "job_id",
        "created_at",
        "updated_at",
    ]

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


@pytest_asyncio.fixture
async def mock_engine():
    """Create a mock engine for testing."""
    mock_engine = MagicMock()
    conn = MockConnection()

    # Add a special method for the applied migrations test
    conn.migrations_result = [("migration1.py",), ("migration2.py",)]

    # No need to override the execute method, MockConnection now handles migrations query

    # Setup both connect and begin methods
    mock_engine.connect = AsyncMock(return_value=AsyncContextManagerMock(conn))
    mock_engine.begin = MagicMock(return_value=AsyncContextManagerMock(conn))

    return mock_engine


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_get_applied_migrations(mock_engine):
    """Test getting applied migrations."""
    # Create migration manager with our mock engine
    manager = MigrationManager(mock_engine)

    # Execute
    result = await manager._get_applied_migrations()

    # Get the connection used in the test
    conn = mock_engine.begin.return_value.return_value

    # Verify
    assert result == {"migration1.py", "migration2.py"}
    assert any("CREATE TABLE IF NOT EXISTS migrations" in q for q in conn.executed)
    assert any("SELECT name FROM migrations" in q for q in conn.executed)
