"""Payload index migration for existing Qdrant collections."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore

from shyhurricane.qdrant_indexes import IndexedQdrantDocumentStore, missing_indexes

FIELDS = [
    {"field_name": "meta.timestamp_float", "field_schema": "float"},
    {"field_name": "meta.host", "field_schema": "keyword"},
]


def test_missing_indexes():
    assert missing_indexes({}, None) == []
    assert missing_indexes({}, FIELDS) == FIELDS
    assert missing_indexes({"meta.host": SimpleNamespace(data_type="keyword")}, FIELDS) == FIELDS[:1]
    with pytest.raises(ValueError, match="meta.host requires type keyword"):
        missing_indexes({"meta.host": SimpleNamespace(data_type="text")}, FIELDS)


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_sync_setup(monkeypatch, present, failure):
    setup = Mock()
    monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection", setup)
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    schema = {item["field_name"]: SimpleNamespace(data_type=item["field_schema"]) for item in FIELDS} if present else {}
    client = Mock()
    client.get_collection.return_value.payload_schema = schema
    if failure:
        client.create_payload_index.side_effect = PermissionError("read only")
    store._client = client
    if failure and not present:
        with pytest.raises(PermissionError):
            store._set_up_collection("network")
    else:
        store._set_up_collection("network")
        assert client.create_payload_index.call_count == (0 if present else len(FIELDS))
    setup.assert_called_once_with("network")
    if not present:
        assert client.create_payload_index.call_args_list[0].kwargs == {
            "collection_name": "network", "wait": True, **FIELDS[0],
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("failure", [False, True])
async def test_async_setup(monkeypatch, present, failure):
    setup = AsyncMock()
    monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection_async", setup)
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    schema = {item["field_name"]: SimpleNamespace(data_type=item["field_schema"]) for item in FIELDS} if present else {}
    client = SimpleNamespace(
        get_collection=AsyncMock(return_value=SimpleNamespace(payload_schema=schema)),
        create_payload_index=AsyncMock(side_effect=PermissionError("read only") if failure else None),
    )
    store._async_client = client
    if failure and not present:
        with pytest.raises(PermissionError):
            await store._set_up_collection_async("network")
    else:
        await store._set_up_collection_async("network")
        assert client.create_payload_index.await_count == (0 if present else len(FIELDS))
    setup.assert_awaited_once_with("network")
    if not present:
        assert client.create_payload_index.call_args_list[0].kwargs == {
            "collection_name": "network", "wait": True, **FIELDS[0],
        }


def test_existing_collection_runs_haystack_setup_before_migration(monkeypatch):
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    client = Mock()
    client.collection_exists.return_value = True
    client.get_collection.return_value.payload_schema = {"meta.host": SimpleNamespace(data_type="keyword")}
    store._client = client
    validate = Mock()
    monkeypatch.setattr(store, "_validate_collection_compatibility", validate)
    store._set_up_collection("network", 768, False, "cosine", True, False)
    validate.assert_called_once()
    client.create_payload_index.assert_called_once_with(collection_name="network", wait=True, **FIELDS[0])
    client.create_collection.assert_not_called()
    client.delete_collection.assert_not_called()


@pytest.mark.asyncio
async def test_existing_collection_runs_async_haystack_setup_before_migration(monkeypatch):
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    client = SimpleNamespace(
        collection_exists=AsyncMock(return_value=True),
        get_collection=AsyncMock(return_value=SimpleNamespace(payload_schema={})),
        create_payload_index=AsyncMock(),
    )
    store._async_client = client
    validate = Mock()
    monkeypatch.setattr(store, "_validate_collection_compatibility", validate)
    await store._set_up_collection_async("network", 768, False, "cosine", True, False)
    validate.assert_called_once()
    assert client.create_payload_index.await_count == len(FIELDS)
