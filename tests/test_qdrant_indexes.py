"""Payload index migration for existing Qdrant collections."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client import AsyncQdrantClient, QdrantClient

from shyhurricane.qdrant_indexes import IndexedQdrantDocumentStore, missing_indexes, short_connect, short_connect_async

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
        http=SimpleNamespace(client=Mock()),
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
        http=SimpleNamespace(client=Mock()),
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


@pytest.mark.parametrize("connect,expected", [(120, 5), (2, 2), (0, 0), (None, 5)])
def test_connection_cap_preserves_other_timeouts(connect, expected):
    request = httpx.Request("PUT", "http://localhost/collections/content/points", extensions={"timeout": {
        "connect": connect, "read": 120, "write": 120, "pool": 17,
    }})
    short_connect(request, lambda value: value)
    assert request.extensions["timeout"] == {"connect": expected, "read": 120, "write": 120, "pool": 17}


@pytest.mark.asyncio
async def test_async_connection_cap_and_disconnect_propagation():
    request = httpx.Request("GET", "http://localhost/")
    failure = httpx.ConnectError("stopped")
    next_request = AsyncMock(side_effect=failure)
    with pytest.raises(httpx.ConnectError) as raised:
        await short_connect_async(request, next_request)
    assert raised.value is failure
    assert request.extensions["timeout"] == {"connect": 5}
    next_request.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_real_qdrant_requests_use_long_io_and_short_connect(monkeypatch, asynchronous):
    requests = []

    def respond(request):
        requests.append(request)
        assert request.extensions["timeout"] == {"connect": 5, "read": 120, "write": 120, "pool": 120}
        return httpx.Response(200, json={"result": {"operation_id": 1, "status": "completed"}, "status": "ok"})

    cls = AsyncQdrantClient if asynchronous else QdrantClient
    client = cls(url="http://localhost:6333", timeout=120, check_compatibility=False,
                 transport=httpx.MockTransport(respond))
    store = IndexedQdrantDocumentStore(index="content", timeout=120)
    if asynchronous:
        store._async_client = client
        monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection_async", AsyncMock())
        monkeypatch.setattr(client, "get_collection", AsyncMock(return_value=SimpleNamespace(payload_schema={})))
        await store._set_up_collection_async()
        result = await client.upsert("content", [], wait=True)
        await client.close()
    else:
        store._client = client
        monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection", Mock())
        monkeypatch.setattr(client, "get_collection", Mock(return_value=SimpleNamespace(payload_schema={})))
        store._set_up_collection()
        result = client.upsert("content", [], wait=True)
        client.close()
    assert result.status == "completed"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_local_clients_do_not_require_http_transport(monkeypatch):
    store = IndexedQdrantDocumentStore(index="content")
    client = QdrantClient(":memory:")
    async_client = AsyncQdrantClient(":memory:")
    store._client = client
    store._async_client = async_client
    monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection", Mock())
    monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection_async", AsyncMock())
    monkeypatch.setattr(client, "get_collection", Mock(return_value=SimpleNamespace(payload_schema={})))
    monkeypatch.setattr(async_client, "get_collection", AsyncMock(return_value=SimpleNamespace(payload_schema={})))
    store._set_up_collection()
    await store._set_up_collection_async()
    client.close()
    await async_client.close()
