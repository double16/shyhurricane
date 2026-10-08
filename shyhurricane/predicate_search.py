"""Select indexed candidates before semantic ranking without reading response bodies."""

from haystack import Document
from qdrant_client.http import models as qm

from shyhurricane.db import scroll_qdrant_collection
from shyhurricane.search_predicates import HTTP_TYPES, resource_key, response_mime
from shyhurricane.utils import documents_sort_unique


async def select_candidates(client, collections, predicates, scope, methods, progress):
    selected = {}
    mime_by_resource = {}
    must = [scope]
    must_not = []
    # Existing ingest records do not normalize method casing; evaluate methods in Python.
    fields = {"status": "status_code", "type": "type"}
    for predicate in predicates:
        if predicate.operator in fields:
            condition = qm.FieldCondition(
                key=f"meta.{fields[predicate.operator]}",
                match=qm.MatchValue(value=int(predicate.value) if predicate.operator == "status" else predicate.value),
            )
            (must_not if predicate.exclude else must).append(condition)
    filtered_scope = qm.Filter(must=must, must_not=must_not)
    collections = sorted(
        (name for name in collections if name.split("_", 1)[0] in HTTP_TYPES),
        key=lambda name: (name != "network", name),
    )
    for collection in collections:
        await progress(f"Filtering indexed {collection} resources")
        candidates = []
        # Read the canonical network MIME even when a type predicate excludes network results.
        collection_scope = scope if collection == "network" else filtered_scope
        async for record in scroll_qdrant_collection(
            client, collection, fields=["meta"], scroll_filter=collection_scope,
        ):
            meta = (record.payload or {}).get("meta", {})
            mime = response_mime(meta)
            key = resource_key(meta)
            if collection == "network":
                mime_by_resource[key] = mime
            if meta.get("type") not in HTTP_TYPES:
                continue
            if methods and meta.get("http_method", "").upper() not in methods:
                continue
            if all(predicate.matches(meta, mime or mime_by_resource.get(key)) for predicate in predicates):
                candidates.append((record.id, meta))
        selected[collection] = candidates
    return selected


def candidate_filters(selected):
    """An empty HasIdCondition deliberately matches no documents."""
    return {
        collection: qm.Filter(must=[qm.HasIdCondition(has_id=[point_id for point_id, _ in candidates])])
        for collection, candidates in selected.items()
    }


async def load_candidates(client, selected, limit):
    # Use metadata to choose the newest unique resources before hydrating their bodies.
    records = [
        (collection, point_id, meta)
        for collection, candidates in selected.items()
        for point_id, meta in candidates
    ]
    records.sort(key=lambda record: (
        record[2].get("timestamp_float", 0),
        record[2].get("type") == "content",
    ), reverse=True)
    chosen = {}
    seen = set()
    for collection, point_id, meta in records:
        key = (meta["url"], meta.get("http_method", "GET"), meta.get("status_code", 200))
        if key in seen:
            continue
        seen.add(key)
        chosen.setdefault(collection, []).append(point_id)
        if len(seen) >= limit:
            break
    documents = []
    for collection, ids in chosen.items():
        points = await client.retrieve(collection_name=collection, ids=ids, with_payload=True, with_vectors=False)
        documents.extend(Document.from_dict(dict(point.payload)) for point in points)
    return documents_sort_unique(documents, limit)
