"""Pytest configuration for SentinelProbe tests."""

import os
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

from sentinelprobe.api.app import app as fastapi_app
from sentinelprobe.core.config import get_settings
from sentinelprobe.core.db import init_db, get_db_session
from sentinelprobe.core.mongodb import connect_to_mongo, close_mongo_connection, get_collection

# Set default asyncio fixture scope
pytest_plugins = ['pytest_asyncio']


class MockEngine:
    """Mock SQLAlchemy AsyncEngine class"""
    
    def __init__(self):
        self._run_ddl_visitor_called = False
    
    def connect(self):
        """Mock connect method that returns a connection with async context manager support."""
        # Create a mock connection that will be returned by __aenter__
        conn = MagicMock()
        
        # Add run_sync method to the connection
        async def run_sync(callable_, *args, **kwargs):
            # Just return a mock result or call the callable with empty args
            if callable_.__name__ == "get_table_names":
                return ["job", "task"]
            return []
            
        conn.run_sync = run_sync
        
        # Create a proper async context manager
        class AsyncContextManager:
            async def __aenter__(self):
                return conn
                
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None
                
        return AsyncContextManager()
    
    def begin(self):
        """Mock begin method that returns a connection with async context manager support."""
        # Create a mock connection that will be returned by __aenter__
        conn = MagicMock()
        
        # Add run_sync method to the connection
        async def run_sync(callable_, *args, **kwargs):
            # Just call the callable with the proper arguments
            if callable_.__name__ == "create_all":
                return callable_(bind=self)
            return callable_(*args, **kwargs)
            
        conn.run_sync = run_sync
        
        # Create a proper async context manager
        class AsyncContextManager:
            async def __aenter__(self):
                return conn
                
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None
                
        return AsyncContextManager()
    
    def dispose(self):
        """Mock dispose method."""
        pass
        
    def _run_ddl_visitor(self, visitor, metadata, **kw):
        """Mock _run_ddl_visitor method."""
        self._run_ddl_visitor_called = True
        return None


class MockSession:
    """Mock SQLAlchemy AsyncSession class"""
    
    def __init__(self):
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.objects = []
        self.deleted_objects = []
        
    def __await__(self):
        async def _await_impl():
            return self
        return _await_impl().__await__()
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    async def commit(self):
        self.committed = True
        
    async def rollback(self):
        self.rolled_back = True
        
    async def close(self):
        self.closed = True
        
    def add(self, obj):
        obj.id = len(self.objects) + 1  # Simulate auto-generated ID
        self.objects.append(obj)
        return obj
        
    async def execute(self, *args, **kwargs):
        # Create a mock result that can be used with scalar() and scalars()
        result = MagicMock()
        
        # For select queries, try to determine the type of object being queried
        if len(args) > 0 and hasattr(args[0], 'whereclause'):
            # Try to determine the type of object being queried
            from sentinelprobe.orchestration.models import Job, Task
            
            # Check if we're querying for Job or Task
            query_str = str(args[0])
            
            # Always return the first object of the appropriate type
            if 'FROM jobs' in query_str:
                # Return the first Job object
                job_objects = [obj for obj in self.objects if isinstance(obj, Job) and obj not in self.deleted_objects]
                result.scalar = AsyncMock(return_value=job_objects[0] if job_objects else None)
                
                # Set up the scalars method
                scalars_result = MagicMock()
                scalars_result.all = AsyncMock(return_value=job_objects)
                result.scalars = AsyncMock(return_value=scalars_result)
            elif 'FROM tasks' in query_str:
                # Return the first Task object
                task_objects = [obj for obj in self.objects if isinstance(obj, Task) and obj not in self.deleted_objects]
                result.scalar = AsyncMock(return_value=task_objects[0] if task_objects else None)
                
                # Set up the scalars method
                scalars_result = MagicMock()
                scalars_result.all = AsyncMock(return_value=task_objects)
                result.scalars = AsyncMock(return_value=scalars_result)
            else:
                result.scalar = AsyncMock(return_value=None)
                
                # Set up the scalars method
                scalars_result = MagicMock()
                scalars_result.all = AsyncMock(return_value=[])
                result.scalars = AsyncMock(return_value=scalars_result)
        
        return result
        
    async def scalar(self, *args, **kwargs):
        # Return the first object or None
        return self.objects[0] if self.objects else None
        
    async def scalars(self, *args, **kwargs):
        # Create a result that has .all() method
        result = MagicMock()
        result.all = AsyncMock(return_value=self.objects)
        return result
    
    async def delete(self, obj):
        # Remove the object from our list
        if obj in self.objects:
            self.objects.remove(obj)
            self.deleted_objects.append(obj)
        # Just a stub for delete operation
        pass


class MockAsyncMongoClient:
    """Mock AsyncIOMotorClient"""
    
    def __init__(self, *args, **kwargs):
        self.db = MockAsyncMongoDatabase()
        self.admin = MagicMock()
        self.admin.command = AsyncMock()
        
    def __getitem__(self, name):
        return self.db
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
        
    def close(self):
        # Not async in the real implementation
        pass


class MockAsyncMongoDatabase:
    """Mock AsyncIOMotorDatabase"""
    
    def __init__(self):
        self.collections = {}
        
    def __getitem__(self, name):
        if name not in self.collections:
            self.collections[name] = MockAsyncMongoCollection(name)
        return self.collections[name]
        
    def get_collection(self, name):
        if name not in self.collections:
            self.collections[name] = MockAsyncMongoCollection(name)
        return self.collections[name]


class MockAsyncMongoCollection:
    """Mock AsyncIOMotorCollection"""
    
    def __init__(self, name):
        self.name = name
        self.documents = []
        self.next_id = 1
        
    async def insert_one(self, document):
        document["_id"] = self.next_id
        self.next_id += 1
        self.documents.append(document)
        result = MagicMock()
        result.inserted_id = document["_id"]
        return result
        
    async def insert_many(self, documents):
        inserted_ids = []
        for doc in documents:
            doc["_id"] = self.next_id
            self.next_id += 1
            self.documents.append(doc)
            inserted_ids.append(doc["_id"])
        result = MagicMock()
        result.inserted_ids = inserted_ids
        return result
        
    async def find_one(self, filter=None, *args, **kwargs):
        if filter is None:
            return self.documents[0] if self.documents else None
            
        for doc in self.documents:
            match = True
            for key, value in filter.items():
                if key not in doc or doc[key] != value:
                    match = False
                    break
            if match:
                return doc
        return None
        
    def find(self, filter=None, *args, **kwargs):
        results = []
        if filter is None:
            results = self.documents.copy()
        else:
            for doc in self.documents:
                match = True
                for key, value in filter.items():
                    if key not in doc or doc[key] != value:
                        match = False
                        break
                if match:
                    results.append(doc)
                    
        # Apply skip and limit
        skip = kwargs.get('skip', 0)
        limit = kwargs.get('limit', 0)
        
        if skip:
            results = results[skip:]
        if limit:
            results = results[:limit]
            
        # Create a cursor-like object
        cursor = MagicMock()
        cursor.to_list = AsyncMock(return_value=results)
        return cursor
        
    async def update_one(self, filter, update, *args, **kwargs):
        # Find the document to update
        doc_to_update = None
        for doc in self.documents:
            match = True
            for key, value in filter.items():
                if key not in doc or doc[key] != value:
                    match = False
                    break
            if match:
                doc_to_update = doc
                break
                
        # Update if found
        if doc_to_update:
            # Handle $set operator
            if "$set" in update:
                for key, value in update["$set"].items():
                    doc_to_update[key] = value
                    
            # Add support for other operators as needed
            
            result = MagicMock()
            result.modified_count = 1
            result.matched_count = 1
            return result
        
        # No document found
        result = MagicMock()
        result.modified_count = 0
        result.matched_count = 0
        return result
        
    async def delete_one(self, filter, *args, **kwargs):
        # Find the document to delete
        for i, doc in enumerate(self.documents):
            match = True
            for key, value in filter.items():
                if key not in doc or doc[key] != value:
                    match = False
                    break
            if match:
                del self.documents[i]
                result = MagicMock()
                result.deleted_count = 1
                return result
                
        # No document found
        result = MagicMock()
        result.deleted_count = 0
        return result


@pytest_asyncio.fixture(scope="function")
async def mock_db_dependencies():
    """Mock database dependencies for testing."""
    # Create mock database engine
    mock_engine = MockEngine()
    
    # Mock MongoDB connection
    mock_mongo_client = MockAsyncMongoClient()
    mock_mongo_collection = MockAsyncMongoCollection("test_collection")
    
    # Create a mock session factory
    def mock_session_factory():
        return MockSession()
    
    # Patch SQLAlchemy engine creation
    with patch("sentinelprobe.core.db.engine", mock_engine), \
         patch("sentinelprobe.core.db.create_async_engine", return_value=mock_engine), \
         patch("sentinelprobe.core.db.AsyncSession", MockSession), \
         patch("sentinelprobe.core.db.async_session_factory", mock_session_factory), \
         patch("sentinelprobe.core.mongodb.mongo_client", mock_mongo_client), \
         patch("sentinelprobe.core.mongodb.db", mock_mongo_client.db), \
         patch("sentinelprobe.core.mongodb.get_collection", return_value=mock_mongo_collection), \
         patch("motor.motor_asyncio.AsyncIOMotorClient", return_value=mock_mongo_client):
        
        # Expose the mocks for test use
        yield {
            "engine": mock_engine,
            "mongo_client": mock_mongo_client,
            "mongo_collection": mock_mongo_collection
        }


@pytest.fixture
def app() -> FastAPI:
    """Get FastAPI application.

    Returns:
        FastAPI: Application instance.
    """
    return fastapi_app


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Get test client for FastAPI application.

    Args:
        app: FastAPI application.

    Yields:
        TestClient: Test client instance.
    """
    with TestClient(app) as test_client:
        yield test_client 