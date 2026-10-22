"""Opt-in Qdrant index checks using an isolated, temporary collection."""

import os
import statistics
import time
import uuid

import pytest
from haystack import Document
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm

from shyhurricane.finding_search import FINDING_SEARCH_FIELDS, finding_predicates, search_findings
from shyhurricane.qdrant_indexes import require_tuned_index_version, tuned_indexes
from shyhurricane.qdrant_reads import scroll_records
from shyhurricane.task_queue.finding_worker import FINDING_VERSION
from tests.test_finding_search import metadata


class ScopedClient:
    """Route production reads only to the collection created by this test."""

    def __init__(self, client, collection):
        self.client = client
        self.collection = collection
        self.candidates = 0
        self.hydrated = 0

    async def scroll(self, **kwargs):
        assert kwargs.pop("collection_name") == "finding"
        result = await self.client.scroll(collection_name=self.collection, **kwargs)
        self.candidates += len(result[0])
        return result

    async def query_points(self, **kwargs):
        assert kwargs.pop("collection_name") == "finding"
        return await self.client.query_points(collection_name=self.collection, **kwargs)

    async def retrieve(self, **kwargs):
        assert kwargs.pop("collection_name") == "finding"
        self.hydrated += len(kwargs["ids"])
        return await self.client.retrieve(collection_name=self.collection, **kwargs)


@pytest.mark.asyncio
@pytest.mark.skipif(not os.environ.get("QDRANT_TEST_URL"), reason="Set QDRANT_TEST_URL for isolated Qdrant checks")
async def test_indexed_finding_search_on_qdrant():
    client = AsyncQdrantClient(url=os.environ["QDRANT_TEST_URL"], timeout=60)
    name = f"finding_predicate_test_{uuid.uuid4().hex}"
    created = False
    try:
        require_tuned_index_version((await client.info()).version)
        await client.create_collection(name, vectors_config=qm.VectorParams(size=2, distance=qm.Distance.DOT))
        created = True
        fields = [{"field_name": f"meta.{field}", "field_schema": "keyword"} for field in FINDING_SEARCH_FIELDS] + [
            {"field_name": "meta.version", "field_schema": "integer"},
            {"field_name": "meta.port", "field_schema": "integer"},
        ]
        for declaration in tuned_indexes(fields):
            await client.create_payload_index(collection_name=name, wait=True, **declaration)
        schema = (await client.get_collection(name)).payload_schema
        for field in FINDING_SEARCH_FIELDS:
            assert schema[f"meta.{field}"].data_type == "keyword"
            assert schema[f"meta.{field}"].params.enable_hnsw is False
        assert schema["meta.port"].params.lookup is True
        assert schema["meta.port"].params.range is False

        points = []
        for index in range(2000):
            host = "api.example.com" if index < 100 else "elsewhere.test"
            path = "admin.js" if index % 10 == 0 else "other.html"
            doc = Document(content=f"Finding {index}", meta=metadata(f"https://{host}/{path}?id={index}"))
            points.append(qm.PointStruct(id=index, vector=[0.1, 0.2], payload=doc.to_dict(flatten=False)))
        # A trigram candidate that must not have its body hydrated.
        doc = Document(content="False positive", meta=metadata("https://api.example.com/adm--dmi--min.js"))
        points.append(qm.PointStruct(id=2000, vector=[0.1, 0.2], payload=doc.to_dict(flatten=False)))
        for start in range(0, len(points), 256):
            await client.upsert(name, points[start : start + 256], wait=True)

        scoped = ScopedClient(client, name)
        baseline_times, indexed_times = [], []
        for _ in range(3):
            started = time.perf_counter()
            baseline = [
                point
                async for point in scroll_records(
                    scoped,
                    "finding",
                    qm.Filter(must=[qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=FINDING_VERSION))]),
                    ["meta.url", "meta.host", "meta.port"],
                )
            ]
            baseline_times.append(time.perf_counter() - started)
            scoped.candidates = scoped.hydrated = 0
            started = time.perf_counter()
            docs = await search_findings(
                scoped, finding_predicates("site:example.com ext:js inurl:admin"), FINDING_VERSION
            )
            indexed_times.append(time.perf_counter() - started)
            assert len(docs) == scoped.hydrated == 10
            assert {doc.content for doc in docs} == {f"Finding {index}" for index in range(0, 100, 10)}
            assert scoped.candidates < len(baseline) == 2001
        print(
            {
                "baseline_records": len(baseline),
                "indexed_candidates": scoped.candidates,
                "hydrated_findings": scoped.hydrated,
                "baseline_median_ms": round(statistics.median(baseline_times) * 1000, 2),
                "indexed_median_ms": round(statistics.median(indexed_times) * 1000, 2),
            }
        )
    finally:
        if created:
            await client.delete_collection(name)
        await client.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not os.environ.get("QDRANT_TEST_URL"), reason="Set QDRANT_TEST_URL for isolated Qdrant checks")
async def test_semantic_finding_ranking_on_qdrant():
    import math

    from haystack_integrations.document_stores.qdrant.document_store import DENSE_VECTORS_NAME

    from shyhurricane.finding_search import finding_ids, load_findings, rank_findings

    client = AsyncQdrantClient(url=os.environ["QDRANT_TEST_URL"], timeout=60)
    name = f"finding_semantic_test_{uuid.uuid4().hex}"
    created = False
    try:
        await client.create_collection(name, vectors_config={
            DENSE_VECTORS_NAME: qm.VectorParams(size=2, distance=qm.Distance.COSINE),
        })
        created = True
        fields = [{"field_name": f"meta.{field}", "field_schema": "keyword"} for field in FINDING_SEARCH_FIELDS]
        fields.append({"field_name": "meta.version", "field_schema": "integer"})
        for declaration in tuned_indexes(fields):
            await client.create_payload_index(collection_name=name, wait=True, **declaration)
        expected = []
        batch = []
        for index in range(5400):
            # Exactly 5,348 eligible findings, with high-scoring out-of-scope distractors.
            url = f"https://example.com/resource/{index}" if index < 5348 else f"https://other.target.local/{index}"
            vector = [1.0, 0.3 + (5349 - index) / 5349] if index < 5348 else [1.0, 0.0]
            if index < 5348:
                expected.append((index, vector[0] / math.sqrt(sum(value * value for value in vector))))
            doc = Document(content=f"Finding {index}", meta=metadata(url))
            batch.append(qm.PointStruct(id=index, vector={DENSE_VECTORS_NAME: vector},
                                        payload=doc.to_dict(flatten=False)))
            if len(batch) == 256 or index == 5399:
                await client.upsert(name, batch, wait=True)
                batch = []
        scoped = ScopedClient(client, name)
        started = time.perf_counter()
        ids = await finding_ids(scoped, finding_predicates("site:example.com"), FINDING_VERSION)
        assert len(ids) == 5348
        points, truncated = await rank_findings(scoped, ids, [1.0, 0.0], None)
        expected.sort(key=lambda item: -item[1])
        assert [point.id for point in points] == [index for index, _ in expected[:1000]]
        assert [point.score for point in points] == pytest.approx([score for _, score in expected[:1000]], abs=1e-6)
        assert truncated
        scores = {str(point.id): point.score for point in points}
        docs = await load_findings(scoped, [point.id for point in points], scores)
        assert len(docs) == scoped.hydrated == 1000
        assert docs[0].content == f"Finding {expected[0][0]}"
        assert docs[0].score == points[0].score
        # Pick a cutoff between ranks 9 and 10, away from floating-point boundaries.
        threshold = (expected[8][1] + expected[9][1]) / 2
        filtered, truncated = await rank_findings(scoped, ids, [1.0, 0.0], threshold)
        assert len(filtered) == 9
        assert not truncated
        print({"eligible_findings": len(ids), "hydrated_findings": scoped.hydrated,
               "semantic_elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    finally:
        if created:
            await client.delete_collection(name)
        await client.close()
