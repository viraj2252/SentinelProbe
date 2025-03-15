"""Pytest configuration for SentinelProbe tests."""

import os
from typing import AsyncGenerator, Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinelprobe.api.app import app as fastapi_app


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