from types import SimpleNamespace

import pytest
from haystack import Document
from qdrant_client.http import models as qm
from qdrant_client.local.payload_filters import check_filter

from shyhurricane import predicate_search
from shyhurricane.search_predicates import Predicate


@pytest.mark.asyncio
async def test_candidate_selection_scans_metadata_and_joins_response_mime(monkeypatch):
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
    assert all(kwargs["fields"] == ["meta"] for _, kwargs in calls)
    assert calls[0][1]["scroll_filter"] == scope
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

    async def scroll(client, collection, fields, scroll_filter):
        if check_filter(scroll_filter, {"meta": meta}, 1, {}):
            yield SimpleNamespace(id=1, payload={"meta": meta})

    async def progress(message):
        pass

    monkeypatch.setattr(predicate_search, "scroll_qdrant_collection", scroll)
    result = await predicate_search.select_candidates(
        None, ["content"], [Predicate("method", "GET", exclude)], qm.Filter(), ["GET"], progress,
    )
    assert bool(result["content"]) is not exclude
