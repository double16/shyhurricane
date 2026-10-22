import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from haystack import Document
from haystack_integrations.document_stores.qdrant.converters import convert_id
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm
from qdrant_client.http.exceptions import ResponseHandlingException

from shyhurricane.qdrant_reads import read_documents, retrieve_records, scroll_records, to_document


@pytest.mark.asyncio
async def test_projected_reads_paginate_limit_and_order_tied_timestamps():
    client = AsyncQdrantClient(":memory:")
    try:
        await client.create_collection("content", vectors_config={})
        await client.upsert("content", [
            qm.PointStruct(id=index, vector={}, payload={
                "id": str(index), "content": "private body", "meta": {
                    "url": f"https://a.test/{index}", "timestamp_float": index // 3,
                },
            }) for index in range(600)
        ])
        scope = qm.Filter()
        fields = ["id", "meta.timestamp_float"]
        points = [point async for point in scroll_records(client, "content", scope, fields)]
        assert [point.id for point in points] == list(range(600))
        assert all("content" not in point.payload for point in points)
        documents = await read_documents(client, "content", scope, limit=1)
        assert [document.id for document in documents] == ["0"]
        assert documents[0].embedding is None
        newest = [point async for point in scroll_records(
            client, "content", scope, fields, newest=True, limit=300,
        )]
        assert len(newest) == len({point.id for point in newest}) == 300
        timestamps = [point.payload["meta"]["timestamp_float"] for point in newest]
        assert timestamps == sorted(timestamps, reverse=True)
        all_newest = [point async for point in scroll_records(client, "content", scope, fields, newest=True)]
        assert len(all_newest) == len({point.id for point in all_newest}) == 600
        empty = await read_documents(client, "content", qm.Filter(must=[qm.HasIdCondition(has_id=[])]))
        assert empty == []
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_retrieve_batches_preserve_order_omit_missing_and_convert_opaque_ids():
    async def retrieve(**kwargs):
        assert len(kwargs["ids"]) <= 128
        assert kwargs["with_vectors"] is False
        return [qm.Record(id=value, payload={"id": str(value)}) for value in reversed(kwargs["ids"]) if value != 5]

    client = SimpleNamespace(retrieve=AsyncMock(side_effect=retrieve))
    points = await retrieve_records(client, "content", list(range(300)), fields=["id"])
    assert [point.id for point in points] == [index for index in range(300) if index != 5]
    assert client.retrieve.call_count == 3
    assert await retrieve_records(client, "content", []) == []

    point_id = str(uuid.UUID(convert_id("opaque")))
    client.retrieve.return_value = [qm.Record(id=point_id, payload={"id": "opaque"})]
    client.retrieve.side_effect = None
    points = await retrieve_records(client, "content", ["opaque"], opaque_ids=True)
    assert [point.id for point in points] == [point_id]
    assert client.retrieve.call_args.kwargs["ids"] == [convert_id("opaque")]


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["scroll", "retrieve"])
async def test_read_failures_propagate_and_redact_payloads(operation, caplog):
    error = ResponseHandlingException(TimeoutError("private URL"))
    client = SimpleNamespace(**{operation: AsyncMock(side_effect=error)})
    with pytest.raises(ResponseHandlingException) as raised:
        if operation == "scroll":
            await read_documents(client, "content", qm.Filter())
        else:
            await retrieve_records(client, "content", [1])
    assert raised.value is error
    assert f"operation={operation}" in caplog.text
    assert "transport_error=TimeoutError" in caplog.text
    assert "private URL" not in caplog.text


def test_document_conversion_preserves_payload_and_handles_absent_payload():
    document = Document(id="opaque", content="body", meta={"url": "https://a.test/"})
    payload = document.to_dict(flatten=False)
    point = qm.Record(id=1, payload=payload)
    assert to_document(point) == document
    assert point.payload == payload
    assert to_document(qm.Record(id=2, payload=None)).content is None
