"""Select indexed candidates before semantic ranking without reading response bodies."""

import logging
import time

from haystack import Document
from qdrant_client.http import models as qm

from shyhurricane.db import scroll_qdrant_collection
from shyhurricane.search_metadata import candidate_scope
from shyhurricane.search_predicates import HTTP_TYPES
from shyhurricane.utils import documents_sort_unique

logger = logging.getLogger(__name__)

CANDIDATE_FIELDS = [f"meta.{field}" for field in (
    "url", "http_method", "status_code", "type", "timestamp", "timestamp_float",
    "content_type", "search_response_mime",
)]


async def select_candidates(client, collections, predicates, scope, methods, progress):
    selected = {}
    filtered_scope = candidate_scope(scope, predicates, methods)
    collections = sorted(
        (name for name in collections if name.split("_", 1)[0] in HTTP_TYPES),
        key=lambda name: (name != "network", name),
    )
    for collection in collections:
        await progress(f"Filtering indexed {collection} resources")
        candidates = []
        started = time.monotonic()
        examined = 0
        try:
            async for record in scroll_qdrant_collection(
                client, collection, fields=CANDIDATE_FIELDS, scroll_filter=filtered_scope, page_size=256,
            ):
                examined += 1
                meta = (record.payload or {}).get("meta", {})
                mime = meta.get("search_response_mime") or None
                if meta.get("type") not in HTTP_TYPES:
                    continue
                if methods and meta.get("http_method", "").upper() not in methods:
                    continue
                if all(predicate.matches(meta, mime) for predicate in predicates):
                    candidates.append((record.id, meta))
        except Exception as error:
            source = getattr(error, "source", error)
            logger.error(
                "Qdrant operation=predicate_scroll collection=%s seconds=%.3f records=%d "
                "error=%s transport_error=%s",
                collection, time.monotonic() - started, examined, type(error).__name__, type(source).__name__,
            )
            raise
        logger.debug(
            "Qdrant predicate collection=%s records=%d candidates=%d seconds=%.3f",
            collection, examined, len(candidates), time.monotonic() - started,
        )
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
