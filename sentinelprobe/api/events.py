"""WebSocket endpoints for streaming Redis events to clients."""

from typing import List, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from sentinelprobe.core.logging import get_logger
from sentinelprobe.core.redis import get_redis_client

logger = get_logger(__name__)

router = APIRouter(prefix="/events", tags=["events"])


@router.websocket("/ws")
async def events_websocket(
    websocket: WebSocket,
    channels: Optional[List[str]] = Query(
        default=None,
        description="Redis channels to subscribe to (default: events:jobs, events:tasks)",
    ),
) -> None:
    """Relays Redis Pub/Sub events to connected clients.

    Query param `channels` can be specified multiple times to override defaults.
    """
    await websocket.accept()
    client = await get_redis_client()
    pubsub = client.pubsub()

    subscribed = channels or ["events:jobs", "events:tasks"]
    try:
        await pubsub.subscribe(*subscribed)
        logger.info(f"WebSocket subscribed to channels: {subscribed}")

        async for message in pubsub.listen():
            # Redis sends control messages; only forward actual messages
            if not isinstance(message, dict):
                continue
            if message.get("type") != "message":
                continue

            payload = {
                "channel": message.get("channel"),
                "data": message.get("data"),
            }
            await websocket.send_json(payload)

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        try:
            await pubsub.unsubscribe(*subscribed)
        except Exception:
            pass
        try:
            await pubsub.close()
        except Exception:
            pass
