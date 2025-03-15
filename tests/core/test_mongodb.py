"""Tests for the MongoDB module."""

import pytest

from sentinelprobe.core.mongodb import get_collection


@pytest.mark.asyncio
async def test_mongodb_connection(mock_db_dependencies):
    """Test connecting to MongoDB."""
    # The mock_db_dependencies fixture already patches the MongoDB connection
    # No need to actually connect, just verify the mocks are in place
    assert mock_db_dependencies["mongo_client"] is not None
    assert mock_db_dependencies["mongo_collection"] is not None


@pytest.mark.asyncio
async def test_get_collection(mock_db_dependencies):
    """Test getting a MongoDB collection."""
    # Get a collection using the mocked function
    collection = get_collection("test_collection")

    # Verify the collection is returned (we don't need to check the exact type
    # since we're using a mock)
    assert collection is not None
    # Check that the collection has the correct name
    assert collection.name == "test_collection"


@pytest.mark.asyncio
async def test_insert_and_find_one(mock_db_dependencies):
    """Test inserting and finding a document."""
    # Get a collection
    collection = get_collection("test_collection")

    # Insert a document
    document = {"name": "test_document", "value": 42, "tags": ["test", "example"]}

    await collection.insert_one(document)

    # Find the document
    found = await collection.find_one({"name": "test_document"})

    # Verify the document was found and has the correct values
    assert found is not None
    assert found["name"] == "test_document"
    assert found["value"] == 42
    assert "tags" in found and len(found["tags"]) == 2


@pytest.mark.asyncio
async def test_find_many(mock_db_dependencies):
    """Test finding multiple documents."""
    # Get a collection
    collection = get_collection("test_collection")

    # Insert several documents
    documents = [
        {"name": "doc1", "category": "test", "value": 1},
        {"name": "doc2", "category": "test", "value": 2},
        {"name": "doc3", "category": "example", "value": 3},
        {"name": "doc4", "category": "test", "value": 4},
        {"name": "doc5", "category": "example", "value": 5},
    ]

    await collection.insert_many(documents)

    # Find documents by category
    cursor = collection.find({"category": "test"})
    results = await cursor.to_list(length=10)

    # Verify we found the right number of documents
    assert len(results) == 3

    # Test with limit
    cursor = collection.find({"category": "test"}, limit=2)
    results = await cursor.to_list(length=10)
    assert len(results) == 2

    # Test with skip
    cursor = collection.find({"category": "test"}, skip=1)
    results = await cursor.to_list(length=10)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_update_one(mock_db_dependencies):
    """Test updating a document."""
    # Get a collection
    collection = get_collection("test_collection")

    # Insert a document
    document = {"name": "update_test", "status": "pending", "count": 1}

    await collection.insert_one(document)

    # Update the document
    result = await collection.update_one(
        {"name": "update_test"}, {"$set": {"status": "completed", "count": 2}}
    )

    # Verify the update was successful
    assert result.modified_count == 1

    # Get the updated document
    updated = await collection.find_one({"name": "update_test"})

    # Verify the changes were applied
    assert updated["status"] == "completed"
    assert updated["count"] == 2


@pytest.mark.asyncio
async def test_delete_one(mock_db_dependencies):
    """Test deleting a document."""
    # Get a collection
    collection = get_collection("test_collection")

    # Insert a document
    document = {"name": "delete_test", "temporary": True}

    await collection.insert_one(document)

    # Confirm the document exists
    found = await collection.find_one({"name": "delete_test"})
    assert found is not None

    # Delete the document
    result = await collection.delete_one({"name": "delete_test"})

    # Verify the delete was successful
    assert result.deleted_count == 1

    # Confirm the document no longer exists
    found = await collection.find_one({"name": "delete_test"})
    assert found is None


@pytest.mark.asyncio
async def test_complex_document(mock_db_dependencies):
    """Test operations with a complex document structure."""
    # Get a collection
    collection = get_collection("test_collection")

    # Insert a complex document
    document = {
        "name": "complex_test",
        "metadata": {
            "created_at": "2023-01-01T12:00:00Z",
            "owner": "test_user",
            "tags": ["complex", "nested", "example"],
        },
        "stats": {"views": 0, "likes": 0, "comments": []},
        "is_active": True,
    }

    await collection.insert_one(document)

    # Find the document
    found = await collection.find_one({"name": "complex_test"})
    assert found is not None
    assert found["metadata"]["owner"] == "test_user"
    assert len(found["metadata"]["tags"]) == 3
    assert found["stats"]["views"] == 0

    # Update nested fields
    result = await collection.update_one(
        {"name": "complex_test"},
        {
            "$set": {
                "stats.views": 10,
                "stats.likes": 5,
                "metadata.tags": ["complex", "nested", "example", "updated"],
            }
        },
    )

    assert result.modified_count == 1

    # Get the updated document
    updated = await collection.find_one({"name": "complex_test"})
    assert updated["stats"]["views"] == 10
    assert updated["stats"]["likes"] == 5
    assert len(updated["metadata"]["tags"]) == 4
    assert "updated" in updated["metadata"]["tags"]
