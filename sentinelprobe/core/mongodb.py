"""MongoDB module for SentinelProbe."""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from sentinelprobe.core.config import get_settings
from sentinelprobe.core.logging import get_logger

logger = get_logger()
settings = get_settings()

# MongoDB client
mongo_client: Optional[AsyncIOMotorClient] = None
db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo() -> None:
    """Connect to MongoDB.

    Initializes the MongoDB client and database.
    """
    global mongo_client, db
    try:
        logger.info("Connecting to MongoDB")
        mongo_client = AsyncIOMotorClient(settings.MONGODB_URL)
        # Verify connection
        await mongo_client.admin.command("ping")
        db_name = settings.MONGODB_URL.split("/")[-1]
        db = mongo_client[db_name]
        logger.info(f"Connected to MongoDB: {db_name}")
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise


async def close_mongo_connection() -> None:
    """Close MongoDB connection."""
    global mongo_client
    if mongo_client:
        logger.info("Closing MongoDB connection")
        mongo_client.close()
        mongo_client = None
        logger.info("MongoDB connection closed")


def get_collection(collection_name: str) -> AsyncIOMotorCollection:
    """Get MongoDB collection.

    Args:
        collection_name: Name of the collection.

    Returns:
        AsyncIOMotorCollection: MongoDB collection.

    Raises:
        ValueError: If database is not initialized.
    """
    if db is None:
        raise ValueError("MongoDB database not initialized")
    return db[collection_name]


async def insert_one(collection_name: str, document: Dict[str, Any]) -> str:
    """Insert a document into a collection.

    Args:
        collection_name: Name of the collection.
        document: Document to insert.

    Returns:
        str: ID of the inserted document.
    """
    collection = get_collection(collection_name)
    result = await collection.insert_one(document)
    return str(result.inserted_id)


async def find_one(collection_name: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Find a document in a collection.

    Args:
        collection_name: Name of the collection.
        query: Query to find the document.

    Returns:
        Optional[Dict[str, Any]]: Found document or None.
    """
    collection = get_collection(collection_name)
    return await collection.find_one(query)


async def find_many(
    collection_name: str, query: Dict[str, Any], limit: int = 0, skip: int = 0
) -> List[Dict[str, Any]]:
    """Find multiple documents in a collection.

    Args:
        collection_name: Name of the collection.
        query: Query to find the documents.
        limit: Maximum number of documents to return.
        skip: Number of documents to skip.

    Returns:
        List[Dict[str, Any]]: List of found documents.
    """
    collection = get_collection(collection_name)
    cursor = collection.find(query).skip(skip)
    if limit > 0:
        cursor = cursor.limit(limit)
    return await cursor.to_list(length=None)


async def update_one(
    collection_name: str, query: Dict[str, Any], update: Dict[str, Any]
) -> int:
    """Update a document in a collection.

    Args:
        collection_name: Name of the collection.
        query: Query to find the document.
        update: Update to apply.

    Returns:
        int: Number of modified documents.
    """
    collection = get_collection(collection_name)
    result = await collection.update_one(query, {"$set": update})
    return result.modified_count


async def delete_one(collection_name: str, query: Dict[str, Any]) -> int:
    """Delete a document from a collection.

    Args:
        collection_name: Name of the collection.
        query: Query to find the document.

    Returns:
        int: Number of deleted documents.
    """
    collection = get_collection(collection_name)
    result = await collection.delete_one(query)
    return result.deleted_count 