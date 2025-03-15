"""Mock session for orchestration tests."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sentinelprobe.orchestration.models import Job, JobStatus, Task, TaskStatus


class MockSession:
    """Mock SQLAlchemy AsyncSession class."""

    def __init__(self):
        """Initialize with empty storage."""
        self.jobs = []
        self.tasks = []
        self.id_counter = 1

    async def __aenter__(self):
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context manager."""
        pass

    async def commit(self):
        """Commit transaction."""
        # Do nothing, just simulate success
        pass

    async def rollback(self):
        """Rollback transaction."""
        # Do nothing, just simulate success
        pass

    async def close(self):
        """Close session."""
        # Do nothing, just simulate success
        pass

    def add(self, obj):
        """Add an object to the session."""
        if isinstance(obj, Job):
            # Set ID if not set
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = self.id_counter
                self.id_counter += 1
            # Set default status
            if not hasattr(obj, "status") or obj.status is None:
                obj.status = JobStatus.PENDING
            # Set timestamps
            if not hasattr(obj, "created_at") or obj.created_at is None:
                obj.created_at = datetime.now(timezone.utc)
            if not hasattr(obj, "updated_at") or obj.updated_at is None:
                obj.updated_at = datetime.now(timezone.utc)
            # Set started_at and completed_at attributes
            if not hasattr(obj, "started_at"):
                obj.started_at = None
            if not hasattr(obj, "completed_at"):
                obj.completed_at = None
            # Ensure config is a string (JSON)
            if hasattr(obj, "config") and isinstance(obj.config, dict):
                obj.config = json.dumps(obj.config)
            self.jobs.append(obj)
        elif isinstance(obj, Task):
            # Set ID if not set
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = self.id_counter
                self.id_counter += 1
            # Set default status
            if not hasattr(obj, "status") or obj.status is None:
                obj.status = TaskStatus.PENDING
            # Set timestamps
            if not hasattr(obj, "created_at") or obj.created_at is None:
                obj.created_at = datetime.now(timezone.utc)
            if not hasattr(obj, "updated_at") or obj.updated_at is None:
                obj.updated_at = datetime.now(timezone.utc)
            # Set started_at and completed_at attributes
            if not hasattr(obj, "started_at"):
                obj.started_at = None
            if not hasattr(obj, "completed_at"):
                obj.completed_at = None
            # Ensure result is a string (JSON)
            if hasattr(obj, "result") and isinstance(obj.result, dict):
                obj.result = json.dumps(obj.result)
            self.tasks.append(obj)

    async def refresh(self, obj):
        """Refresh an object from the database."""
        # Nothing to do, this is a mock
        pass

    async def execute(self, statement):
        """Execute a statement."""
        # Handle different statement types
        try:
            # Try to get the entity class from the statement
            model_class = getattr(statement, "entity_class", None)

            # Handle different model classes
            if model_class == Job:
                where_clause = getattr(statement, "whereclause", None)
                job_id = None
                status = None

                # Extract conditions (very simplified)
                if where_clause:
                    if hasattr(where_clause, "right") and hasattr(where_clause, "left"):
                        if str(where_clause.left) == "jobs.id":
                            job_id = where_clause.right.value
                        elif str(where_clause.left) == "jobs.status":
                            status = where_clause.right.value

                # Filter based on conditions
                if job_id is not None:
                    filtered_jobs = [job for job in self.jobs if job.id == job_id]
                elif status is not None:
                    filtered_jobs = [job for job in self.jobs if job.status == status]
                else:
                    filtered_jobs = self.jobs.copy()

                # Create a mock result with filtered data
                return MockResult(filtered_jobs)

            elif model_class == Task:
                where_clause = getattr(statement, "whereclause", None)
                task_id = None
                job_id = None

                # Extract conditions (very simplified)
                if where_clause:
                    if hasattr(where_clause, "right") and hasattr(where_clause, "left"):
                        if str(where_clause.left) == "tasks.id":
                            task_id = where_clause.right.value
                        elif str(where_clause.left) == "tasks.job_id":
                            job_id = where_clause.right.value

                # Filter based on conditions
                if task_id is not None:
                    filtered_tasks = [task for task in self.tasks if task.id == task_id]
                elif job_id is not None:
                    filtered_tasks = [
                        task for task in self.tasks if task.job_id == job_id
                    ]
                else:
                    filtered_tasks = self.tasks.copy()

                # Create a mock result with filtered data
                return MockResult(filtered_tasks)
        except Exception as e:
            print(f"Error in mock execute: {e}")

        # Default empty result
        return MockResult([])


class MockResult:
    """Mock SQLAlchemy result."""

    def __init__(self, data):
        """Initialize with data."""
        self.data = data

    def scalar_one_or_none(self):
        """Return the first result or None."""
        return self.data[0] if self.data else None

    def scalars(self):
        """Return a mock scalars result."""
        return self

    def all(self):
        """Return all data."""
        return self.data
