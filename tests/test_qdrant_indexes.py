"""Tuned payload index creation and missing-index repair."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client import AsyncQdrantClient, QdrantClient
from qdrant_client.http import models as qm

from shyhurricane.qdrant_indexes import (
    IndexedQdrantDocumentStore,
    missing_indexes,
    require_tuned_index_version,
    short_connect,
    short_connect_async,
    tuned_indexes,
)

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
    client.info.return_value.version = "1.17.0"
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
            "collection_name": "network", "wait": True, **tuned_indexes(FIELDS)[0],
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
        info=AsyncMock(return_value=SimpleNamespace(version="1.17.0")),
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
            "collection_name": "network", "wait": True, **tuned_indexes(FIELDS)[0],
        }


def test_missing_index_repair_uses_tuning_after_haystack_validation(monkeypatch):
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    client = Mock()
    client.collection_exists.return_value = True
    client.get_collection.return_value.payload_schema = {"meta.host": SimpleNamespace(data_type="keyword")}
    client.info.return_value.version = "1.17.0"
    store._client = client
    validate = Mock()
    monkeypatch.setattr(store, "_validate_collection_compatibility", validate)
    store._set_up_collection("network", 768, False, "cosine", True, False)
    validate.assert_called_once()
    client.create_payload_index.assert_called_once_with(
        collection_name="network", wait=True, **tuned_indexes(FIELDS)[0],
    )
    client.create_collection.assert_not_called()
    client.delete_collection.assert_not_called()


@pytest.mark.asyncio
async def test_async_missing_index_repair_uses_tuning_after_haystack_validation(monkeypatch):
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=FIELDS)
    client = SimpleNamespace(
        http=SimpleNamespace(client=Mock()),
        collection_exists=AsyncMock(return_value=True),
        get_collection=AsyncMock(return_value=SimpleNamespace(payload_schema={})),
        info=AsyncMock(return_value=SimpleNamespace(version="1.17.0")),
        create_payload_index=AsyncMock(),
    )
    store._async_client = client
    validate = Mock()
    monkeypatch.setattr(store, "_validate_collection_compatibility", validate)
    await store._set_up_collection_async("network", 768, False, "cosine", True, False)
    validate.assert_called_once()
    assert client.create_payload_index.await_count == len(FIELDS)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("version", ["1.17.0", "1.16.9", "failure"])
async def test_missing_integer_index_repair_and_version_guard(monkeypatch, asynchronous, version):
    fields = [{"field_name": f"meta.{name}", "field_schema": "integer"}
              for name in ("version", "port", "status_code")]
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=fields)
    info = Mock(return_value=SimpleNamespace(version=version))
    if version == "failure":
        info.side_effect = ConnectionError("unavailable")
    client = Mock()
    if asynchronous:
        monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection_async", AsyncMock())
        client.info = AsyncMock(return_value=info.return_value, side_effect=info.side_effect)
        client.get_collection = AsyncMock(return_value=SimpleNamespace(payload_schema={}))
        client.create_payload_index = AsyncMock()
        store._async_client = client
    else:
        monkeypatch.setattr(QdrantDocumentStore, "_set_up_collection", Mock())
        client.info = info
        client.get_collection.return_value.payload_schema = {}
        store._client = client

    async def run_setup():
        if asynchronous:
            await store._set_up_collection_async()
        else:
            store._set_up_collection()

    if version != "1.17.0":
        with pytest.raises(ConnectionError if version == "failure" else ValueError):
            await run_setup()
        client.create_payload_index.assert_not_called()
        return

    await run_setup()
    assert client.create_payload_index.call_count == len(fields)
    for call in client.create_payload_index.call_args_list:
        params = call.kwargs["field_schema"]
        assert params.lookup is True
        assert params.range is False
        assert params.enable_hnsw == (call.kwargs["field_name"] != "meta.port")


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


@pytest.mark.parametrize("schema", [
    "integer", {"type": "integer"}, qm.IntegerIndexParams(type="integer", on_disk=True),
])
def test_parameterized_indexes_preserve_type_and_memory(schema):
    fields = [{"field_name": "meta.port", "field_schema": schema}]
    tuned = tuned_indexes(fields)
    params = tuned[0]["field_schema"]
    assert params.lookup is True
    assert params.range is False
    assert params.enable_hnsw is False
    assert params.on_disk == (True if isinstance(schema, qm.IntegerIndexParams) else None)
    assert fields[0]["field_schema"] == schema
    assert missing_indexes({"meta.port": SimpleNamespace(data_type="integer")}, tuned) == []
    with pytest.raises(ValueError, match="requires type integer"):
        missing_indexes({"meta.port": SimpleNamespace(data_type="keyword")}, tuned)
    assert tuned_indexes(None) == []


@pytest.mark.parametrize("version", ["1.17.0", "1.18.2", "2.0.0", "1.17.0+build"])
def test_tuned_index_supported_versions(version):
    require_tuned_index_version(version)


@pytest.mark.parametrize("version", ["1.16.9", "0.17.0", "unknown", "1.17"])
def test_tuned_index_unsupported_versions(version):
    with pytest.raises(ValueError, match="requires Qdrant 1.17"):
        require_tuned_index_version(version)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("version", ["1.17.0", "1.16.9", "failure"])
async def test_new_collection_tuning_and_version_guard(monkeypatch, asynchronous, version):
    fields = [
        {"field_name": "meta.version", "field_schema": "integer"},
        {"field_name": "meta.port", "field_schema": "integer"},
        *FIELDS,
    ]
    store = IndexedQdrantDocumentStore(index="network", payload_fields_to_index=fields)
    client = Mock()
    schema = {}
    client.collection_exists.return_value = False
    client.get_collection.return_value = SimpleNamespace(payload_schema=schema)
    client.info.return_value = SimpleNamespace(version=version)
    if version == "failure":
        client.info.side_effect = ConnectionError("unavailable")

    def record_index(**kwargs):
        params = kwargs["field_schema"]
        schema[kwargs["field_name"]] = SimpleNamespace(data_type=params.type, params=params)

    client.create_payload_index.side_effect = record_index
    if asynchronous:
        for name in ["collection_exists", "get_collection", "info", "create_collection",
                     "delete_collection", "create_payload_index"]:
            method = getattr(client, name)
            setattr(client, name, AsyncMock(return_value=method.return_value, side_effect=method.side_effect))
        store._async_client = client
        setup = store._set_up_collection_async
    else:
        store._client = client
        setup = store._set_up_collection

    async def run_setup():
        result = setup("network", 768, False, "cosine", True, False, payload_fields_to_index=fields)
        if asynchronous:
            await result

    if version != "1.17.0":
        error = ConnectionError if version == "failure" else ValueError
        with pytest.raises(error):
            await run_setup()
        client.create_collection.assert_not_called()
        client.delete_collection.assert_not_called()
        client.create_payload_index.assert_not_called()
        return

    await run_setup()
    client.create_collection.assert_called_once()
    assert client.create_payload_index.call_count == len(fields)
    assert schema["meta.version"].params.enable_hnsw is True
    assert schema["meta.port"].params.enable_hnsw is False
    assert schema["meta.timestamp_float"].params.type == "float"
    assert schema["meta.timestamp_float"].params.enable_hnsw is False
    assert all(call.kwargs["wait"] is True for call in client.create_payload_index.call_args_list)

    client.collection_exists.return_value = True
    monkeypatch.setattr(store, "_validate_collection_compatibility", Mock())
    await run_setup()
    assert client.create_payload_index.call_count == len(fields)
    client.info.assert_called_once()


@pytest.mark.asyncio
async def test_recreate_without_payload_indexes_needs_no_version_check(monkeypatch):
    store = IndexedQdrantDocumentStore(index="empty")
    sync = Mock()
    async_setup = AsyncMock()
    monkeypatch.setattr(QdrantDocumentStore, "recreate_collection", sync)
    monkeypatch.setattr(QdrantDocumentStore, "recreate_collection_async", async_setup)
    store.recreate_collection("empty")
    await store.recreate_collection_async("empty")
    sync.assert_called_once_with("empty")
    async_setup.assert_awaited_once_with("empty")
