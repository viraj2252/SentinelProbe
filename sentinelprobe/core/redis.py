"""Redis module for SentinelProbe."""

import json
from typing import Any, Dict, List, Optional, Union

import redis.asyncio as redis
from redis.asyncio import Redis
from redis.exceptions import RedisError

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.logging import get_logger

logger = get_logger()
settings = get_settings()

# Redis client
redis_client: Optional[Redis] = None


async def connect_to_redis() -> None:
    """Connect to Redis.

    Initializes the Redis client.
    """
    global redis_client
    try:
        logger.info("Connecting to Redis")
        redis_client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
        )
        # Verify connection
        await redis_client.ping()
        logger.info("Connected to Redis")
    except RedisError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise


async def close_redis_connection() -> None:
    """Close Redis connection."""
    global redis_client
    if redis_client:
        logger.info("Closing Redis connection")
        await redis_client.close()
        redis_client = None
        logger.info("Redis connection closed")


def get_redis() -> Redis:
    """Get Redis client.

    Returns:
        Redis: Redis client.

    Raises:
        ValueError: If Redis client is not initialized.
    """
    if redis_client is None:
        raise ValueError("Redis client not initialized")
    return redis_client


async def set_key(key: str, value: Union[str, Dict[str, Any], List[Any]], expire: int = 0) -> bool:
    """Set a key in Redis.

    Args:
        key: Key to set.
        value: Value to set.
        expire: Expiration time in seconds.

    Returns:
        bool: True if successful.
    """
    redis_instance = get_redis()
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    await redis_instance.set(key, value)
    if expire > 0:
        await redis_instance.expire(key, expire)
    return True


async def get_key(key: str) -> Optional[str]:
    """Get a key from Redis.

    Args:
        key: Key to get.

    Returns:
        Optional[str]: Value of the key or None.
    """
    redis_instance = get_redis()
    return await redis_instance.get(key)


async def get_json(key: str) -> Optional[Union[Dict[str, Any], List[Any]]]:
    """Get a JSON value from Redis.

    Args:
        key: Key to get.

    Returns:
        Optional[Union[Dict[str, Any], List[Any]]]: JSON value or None.
    """
    value = await get_key(key)
    if value:
        return json.loads(value)
    return None


async def delete_key(key: str) -> int:
    """Delete a key from Redis.

    Args:
        key: Key to delete.

    Returns:
        int: Number of deleted keys.
    """
    redis_instance = get_redis()
    return await redis_instance.delete(key)


async def set_hash(hash_key: str, field: str, value: str) -> int:
    """Set a field in a hash.

    Args:
        hash_key: Hash key.
        field: Field to set.
        value: Value to set.

    Returns:
        int: 1 if field is new, 0 if field was updated.
    """
    redis_instance = get_redis()
    return await redis_instance.hset(hash_key, field, value)


async def get_hash(hash_key: str, field: str) -> Optional[str]:
    """Get a field from a hash.

    Args:
        hash_key: Hash key.
        field: Field to get.

    Returns:
        Optional[str]: Value of the field or None.
    """
    redis_instance = get_redis()
    return await redis_instance.hget(hash_key, field)


async def get_all_hash(hash_key: str) -> Dict[str, str]:
    """Get all fields from a hash.

    Args:
        hash_key: Hash key.

    Returns:
        Dict[str, str]: All fields and values.
    """
    redis_instance = get_redis()
    return await redis_instance.hgetall(hash_key)


async def delete_hash_field(hash_key: str, field: str) -> int:
    """Delete a field from a hash.

    Args:
        hash_key: Hash key.
        field: Field to delete.

    Returns:
        int: Number of deleted fields.
    """
    redis_instance = get_redis()
    return await redis_instance.hdel(hash_key, field) 