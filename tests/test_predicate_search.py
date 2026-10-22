from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from haystack import Document
from qdrant_client.http import models as qm
from qdrant_client.local.payload_filters import check_filter

from shyhurricane import predicate_search
from shyhurricane.search_metadata import derive_search_metadata
from shyhurricane.search_predicates import Predicate


@pytest.mark.asyncio
async def test_candidate_selection_traverses_all_qdrant_pages():
    def record(index):
        return SimpleNamespace(id=index, payload={"meta": {
            "url": f"https://example.test/{index}", "type": "network", "content_type": "text/html",
        }})

    client = SimpleNamespace(scroll=AsyncMock(side_effect=[
        ([record(index) for index in range(1000)], 999), ([record(1000)], None),
    ]))
    selected = await predicate_search.select_candidates(client, ["network"], [], qm.Filter(), [], AsyncMock())
    assert [point_id for point_id, _ in selected["network"]] == list(range(1001))


@pytest.mark.asyncio
async def test_candidate_selection_reads_small_metadata_and_stored_response_mime(monkeypatch):
    shared = {"url": "https://example.com/form", "http_method": "GET", "status_code": 200, "timestamp": "t"}
    records = {
        "network": [SimpleNamespace(id=1, payload={"meta": shared | {
            "type": "network", "content_type": "text/plain",
            "response_headers": '{"Content-Type": "text/html"}',
        }})],
        "forms_256": [SimpleNamespace(id=2, payload={"meta": shared | {
            "type": "forms", "content_type": "text/json",
        }})],
        "content": [
            SimpleNamespace(id=3, payload={"meta": shared | {"type": "content", "content_type": "text/html"}}),
            SimpleNamespace(id=4, payload={"meta": shared | {"type": "content", "http_method": "POST"}}),
            SimpleNamespace(id=5, payload={"meta": shared | {"type": "finding"}}),
            SimpleNamespace(id=6, payload=None),
        ],
    }
    for points in records.values():
        for point in points:
            if point.payload:
                point.payload["meta"]["search_response_mime"] = "text/html"
    calls = []

    async def scroll(client, collection, **kwargs):
        calls.append((collection, kwargs))
        for record in records[collection]:
            yield record

    monkeypatch.setattr(predicate_search, "scroll_qdrant_collection", scroll)
    progress = []

    async def report(message):
        progress.append(message)

    scope = qm.Filter(must=[qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=1))])
    selected = await predicate_search.select_candidates(
        None, ["forms_256", "network", "content", "finding", "nmap"],
        [Predicate("mime", "text/html")], scope, ["GET"], report,
    )
    assert {collection: [point_id for point_id, _ in points] for collection, points in selected.items()} == {
        "network": [1], "content": [3], "forms_256": [2],
    }
    assert calls[0][0] == "network"
    assert all(kwargs["fields"] == predicate_search.CANDIDATE_FIELDS for _, kwargs in calls)
    assert all(kwargs["page_size"] == 256 for _, kwargs in calls)
    assert calls[0][1]["scroll_filter"].must[0] == scope
    assert calls[1][1]["scroll_filter"].must[0] == scope
    assert len(progress) == 3
    filters = predicate_search.candidate_filters(selected | {"html": []})
    assert filters["network"].must[0].has_id == [1]
    assert filters["html"].must[0].has_id == []


@pytest.mark.asyncio
async def test_load_candidates_sorts_deduplicates_and_hydrates_only_limit():
    meta = {"url": "https://example.com/", "http_method": "GET", "status_code": 200, "type": "content"}
    selected = {
        "content": [(1, meta | {"timestamp_float": 2}), (2, meta | {"timestamp_float": 1})],
        "network": [(3, meta | {"timestamp_float": 3, "type": "network"}),
                    (4, meta | {"url": "https://example.com/b", "timestamp_float": 0})],
    }

    class Client:
        def __init__(self):
            self.calls = []

        async def retrieve(self, **kwargs):
            self.calls.append(kwargs)
            return [SimpleNamespace(payload=Document(id="3", content="headers", meta=meta).to_dict(flatten=False))]

    client = Client()
    documents = await predicate_search.load_candidates(client, selected, 1)
    assert len(documents) == 1
    assert client.calls == [{"collection_name": "network", "ids": [3], "with_payload": True, "with_vectors": False}]
    assert await predicate_search.load_candidates(client, {}, 10) == []


@pytest.mark.asyncio
async def test_load_candidates_skips_duplicate_resources():
    meta = {"url": "https://example.com/", "type": "content"}

    class Client:
        async def retrieve(self, **kwargs):
            assert kwargs["ids"] == [1, 3]
            return [SimpleNamespace(payload=Document(id=str(index), content="body", meta=value).to_dict(flatten=False))
                    for index, value in [(1, meta), (3, meta | {"url": "https://example.com/b"})]]

    result = await predicate_search.load_candidates(
        Client(), {"content": [(1, meta), (2, meta), (3, meta | {"url": "https://example.com/b"})]}, 10,
    )
    assert len(result) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("exclude", [False, True])
async def test_candidate_methods_match_existing_mixed_case_records(monkeypatch, exclude):
    meta = {"type": "content", "url": "https://example.com/", "http_method": "get"}

    meta.update(derive_search_metadata(meta["url"], meta["http_method"], {}))

    async def scroll(client, collection, fields, scroll_filter, page_size):
        if check_filter(scroll_filter, {"meta": meta}, 1, {}):
            yield SimpleNamespace(id=1, payload={"meta": meta})

    async def progress(message):
        pass

    monkeypatch.setattr(predicate_search, "scroll_qdrant_collection", scroll)
    result = await predicate_search.select_candidates(
        None, ["content"], [Predicate("method", "GET", exclude)], qm.Filter(), ["GET"], progress,
    )
    assert bool(result["content"]) is not exclude


@pytest.mark.asyncio
async def test_candidate_read_failure_propagates_without_fallback(caplog):
    from qdrant_client.http.exceptions import ResponseHandlingException

    error = ResponseHandlingException(TimeoutError("private URL should not appear"))
    client = SimpleNamespace(scroll=AsyncMock(side_effect=error))
    with pytest.raises(ResponseHandlingException) as raised:
        await predicate_search.select_candidates(client, ["network"], [], qm.Filter(), [], AsyncMock())
    assert raised.value is error
    assert client.scroll.call_count == 1
    assert "operation=predicate_scroll" in caplog.text
    assert "transport_error=TimeoutError" in caplog.text
    assert "private URL" not in caplog.text


@pytest.mark.asyncio
async def test_real_local_qdrant_filters_and_projects_candidates():
    from qdrant_client import AsyncQdrantClient

    client = AsyncQdrantClient(":memory:")
    try:
        await client.create_collection("network", vectors_config={})
        points = []
        for index in range(600):
            path = f"/audit-defense/{index}" if index % 100 == 0 else f"/other/{index}"
            url = f"https://example.test{path}"
            meta = {
                "url": url, "http_method": "gEt", "type": "network", "status_code": 200,
                "timestamp_float": index, "response_headers": "private headers" * 1000,
                **derive_search_metadata(url, "gEt", {"Content-Type": "text/html"}),
            }
            points.append(qm.PointStruct(id=index, vector={}, payload={"meta": meta}))
        await client.upsert("network", points)
        progress = AsyncMock()
        from shyhurricane.search_predicates import parse_predicates

        _, predicates = parse_predicates("inurl:/audit-defense/ mime:text/html method:get")
        result = await predicate_search.select_candidates(
            client, ["network"], predicates, qm.Filter(), [], progress,
        )
        assert [point_id for point_id, _ in result["network"]] == list(range(0, 600, 100))
        for _, meta in result["network"]:
            assert "response_headers" not in meta
            assert "search_url_trigrams" not in meta
            assert meta["search_response_mime"] == "text/html"
        # Broad results still traverse all pages, without truncating at the page size.
        result = await predicate_search.select_candidates(client, ["network"], [], qm.Filter(), [], progress)
        assert len(result["network"]) == 600
    finally:
        await client.close()
