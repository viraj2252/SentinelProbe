"""MongoDB module for SentinelProbe."""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# MongoDB client instance
mongo_client: Optional[AsyncIOMotorClient] = None
db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo() -> None:
    """
    Connect to MongoDB.

    This function initializes the MongoDB client and database connection.
    It should be called during application startup.
    """
    global mongo_client, db

    if mongo_client is not None:
        return

    logger.info("Connecting to MongoDB")

    try:
        mongo_client = AsyncIOMotorClient(
            settings.mongo_uri, serverSelectionTimeoutMS=5000
        )

        # Verify connection
        await mongo_client.server_info()

        # Get database
        db = mongo_client[settings.mongo_db]

        logger.info(f"Connected to MongoDB: {settings.mongo_uri}")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        mongo_client = None
        db = None
        raise


async def close_mongo_connection() -> None:
    """
    Close MongoDB connection.

    This function closes the MongoDB client connection.
    It should be called during application shutdown.
    """
    global mongo_client, db

    if mongo_client is None:
        return

    logger.info("Closing MongoDB connection")
    mongo_client.close()
    mongo_client = None
    db = None


async def get_collection(collection_name: str) -> AsyncIOMotorCollection:
    """
    Get a MongoDB collection by name.

    Args:
        collection_name: Name of the collection to retrieve

    Returns:
        AsyncIOMotorCollection: The requested MongoDB collection
    """
    if db is None:
        await connect_to_mongo()

    if db is None:
        raise RuntimeError("MongoDB connection failed")

    return db[collection_name]


async def insert_one(collection_name: str, document: Dict[str, Any]) -> str:
    """
    Insert a document into a collection.

    Args:
        collection_name: Name of the collection
        document: Document to insert

    Returns:
        str: ID of the inserted document
    """
    collection = await get_collection(collection_name)
    result = await collection.insert_one(document)
    return str(result.inserted_id)


async def find_one(
    collection_name: str, query: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Find a document in a collection.

    Args:
        collection_name: Name of the collection
        query: Query to find the document

    Returns:
        Optional[Dict[str, Any]]: Found document or None
    """
    collection = await get_collection(collection_name)
    result = await collection.find_one(query)
    return result


async def find_many(
    collection_name: str, query: Dict[str, Any], limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Find multiple documents in a collection.

    Args:
        collection_name: Name of the collection
        query: Query to find documents
        limit: Maximum number of documents to return

    Returns:
        List[Dict[str, Any]]: List of found documents
    """
    collection = await get_collection(collection_name)
    cursor = collection.find(query).limit(limit)
    return await cursor.to_list(length=limit)


async def update_one(
    collection_name: str, query: Dict[str, Any], update: Dict[str, Any]
) -> int:
    """
    Update a document in a collection.

    Args:
        collection_name: Name of the collection
        query: Query to find the document
        update: Update to apply

    Returns:
        int: Number of modified documents
    """
    collection = await get_collection(collection_name)
    result = await collection.update_one(query, {"$set": update})
    return result.modified_count


async def delete_one(collection_name: str, query: Dict[str, Any]) -> int:
    """
    Delete a document from a collection.

    Args:
        collection_name: Name of the collection
        query: Query to find the document

    Returns:
        int: Number of deleted documents
    """
    collection = await get_collection(collection_name)
    result = await collection.delete_one(query)
    return result.deleted_count
