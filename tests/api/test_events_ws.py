"""Tests for WebSocket events endpoint using mocked Redis Pub/Sub."""

from typing import Any, AsyncIterator, Dict
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from sentinelprobe.api.app import app
from sentinelprobe.core.config import get_settings


class _MockPubSub:
    async def subscribe(self, *args: str) -> None:  # noqa: D401 - test helper
        return None

    async def unsubscribe(self, *args: str) -> None:  # noqa: D401 - test helper
        return None

    async def close(self) -> None:  # noqa: D401 - test helper
        return None

    async def listen(self) -> AsyncIterator[Dict[str, Any]]:  # noqa: D401 - test helper
        # Yield a single message, then end the stream
        yield {"type": "message", "channel": "events:jobs", "data": '{"ok":true}'}


class _MockRedis:
    def pubsub(self) -> _MockPubSub:  # noqa: D401 - test helper
        return _MockPubSub()


def test_events_websocket_streams_messages() -> None:
    """Ensure WebSocket returns a forwarded Redis message from mocked pub/sub."""
    settings = get_settings()
    ws_path = f"{settings.API_PREFIX}/events/ws?channels=events:jobs"

    # Patch the Redis client getter to return our mock client
    with patch(
        "sentinelprobe.api.events.get_redis_client",
        new=AsyncMock(return_value=_MockRedis()),
    ):
        client = TestClient(app)
        with client.websocket_connect(ws_path) as ws:
            message = ws.receive_json()
            assert message["channel"] == "events:jobs"
            assert message["data"] == '{"ok":true}'


class _MockPubSubMulti:
    async def subscribe(self, *args: str) -> None:
        return None

    async def unsubscribe(self, *args: str) -> None:
        return None

    async def close(self) -> None:
        return None

    async def listen(self) -> AsyncIterator[Dict[str, Any]]:
        # Simulate control and multiple channel messages
        yield {"type": "subscribe", "channel": "events:jobs", "data": 1}
        yield {"type": "message", "channel": "events:jobs", "data": "job-msg"}
        yield {"type": "message", "channel": "events:tasks", "data": "task-msg"}


class _MockRedisMulti:
    def pubsub(self) -> _MockPubSubMulti:
        return _MockPubSubMulti()


def test_events_websocket_multiple_channels_and_control_messages() -> None:
    """Ensure WebSocket forwards only 'message' types across multiple channels."""
    settings = get_settings()
    ws_path = (
        f"{settings.API_PREFIX}/events/ws?channels=events:jobs&channels=events:tasks"
    )

    with patch(
        "sentinelprobe.api.events.get_redis_client",
        new=AsyncMock(return_value=_MockRedisMulti()),
    ):
        client = TestClient(app)
        with client.websocket_connect(ws_path) as ws:
            msg1 = ws.receive_json()
            msg2 = ws.receive_json()
            assert {msg1["channel"], msg2["channel"]} == {"events:jobs", "events:tasks"}
            assert {msg1["data"], msg2["data"]} == {"job-msg", "task-msg"}


class _MockPubSubTasksOnly:
    async def subscribe(self, *args: str) -> None:
        return None

    async def unsubscribe(self, *args: str) -> None:
        return None

    async def close(self) -> None:
        return None

    async def listen(self) -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "message", "channel": "events:tasks", "data": "ok"}


class _MockRedisTasksOnly:
    def pubsub(self) -> _MockPubSubTasksOnly:
        return _MockPubSubTasksOnly()


def test_events_websocket_channels_query_override() -> None:
    """Ensure channels query filters to requested channels only."""
    settings = get_settings()
    ws_path = f"{settings.API_PREFIX}/events/ws?channels=events:tasks"

    with patch(
        "sentinelprobe.api.events.get_redis_client",
        new=AsyncMock(return_value=_MockRedisTasksOnly()),
    ):
        client = TestClient(app)
        with client.websocket_connect(ws_path) as ws:
            msg = ws.receive_json()
            assert msg["channel"] == "events:tasks"
            assert msg["data"] == "ok"


class _MockPubSubRaises:
    async def subscribe(self, *args: str) -> None:
        return None

    async def unsubscribe(self, *args: str) -> None:
        return None

    async def close(self) -> None:
        return None

    async def listen(self) -> AsyncIterator[Dict[str, Any]]:
        raise RuntimeError("listen failed")


class _MockRedisRaises:
    def pubsub(self) -> _MockPubSubRaises:
        return _MockPubSubRaises()


def test_events_websocket_handles_errors_gracefully() -> None:
    """Ensure server doesn't crash when pub/sub listen raises."""
    settings = get_settings()
    ws_path = f"{settings.API_PREFIX}/events/ws?channels=events:jobs"

    with patch(
        "sentinelprobe.api.events.get_redis_client",
        new=AsyncMock(return_value=_MockRedisRaises()),
    ):
        client = TestClient(app)
        # Connection may close immediately due to error; just ensure no exception escapes
        with client.websocket_connect(ws_path):
            pass
