"""Vector-free Qdrant reads for interactive tools."""

import logging
import time

from haystack_integrations.document_stores.qdrant.converters import (
    convert_id,
    convert_qdrant_point_to_haystack_document,
)
from qdrant_client.http import models as qm

logger = logging.getLogger(__name__)


def _failure(operation, collection, started, error):
    source = getattr(error, "source", error)
    logger.error(
        "Qdrant operation=%s collection=%s seconds=%.3f error=%s transport_error=%s",
        operation, collection, time.monotonic() - started, type(error).__name__, type(source).__name__,
    )


def to_document(point):
    # The integration converter modifies payloads; keep the transport record intact.
    return convert_qdrant_point_to_haystack_document(
        point.model_copy(update={"payload": dict(point.payload or {})}), use_sparse_embeddings=True,
    )


async def scroll_records(client, collection, filters, fields, *, limit=None, newest=False):
    """Yield projected records in 256-record pages, optionally ordered by timestamp."""
    started = time.monotonic()
    requests = count = 0
    offset = None
    seen = []
    try:
        while limit is None or count < limit:
            size = min(256, limit - count) if limit is not None else 256
            page_filter = filters
            if newest and seen:
                page_filter = qm.Filter(must=[filters], must_not=[qm.HasIdCondition(has_id=seen)])
            records, offset = await client.scroll(
                collection_name=collection, scroll_filter=page_filter, limit=size,
                offset=None if newest else offset, with_payload=fields, with_vectors=False,
                order_by=qm.OrderBy(key="meta.timestamp_float", direction=qm.Direction.DESC) if newest else None,
            )
            requests += 1
            count += len(records)
            if newest:
                seen.extend(record.id for record in records)
            for record in records:
                yield record
            if (newest and len(records) < size) or (not newest and offset is None):
                break
    except Exception as error:
        _failure("scroll", collection, started, error)
        raise
    finally:
        logger.debug(
            "Qdrant operation=scroll collection=%s requests=%d records=%d seconds=%.3f",
            collection, requests, count, time.monotonic() - started,
        )


async def read_documents(client, collection, filters, fields=True, *, limit=None):
    return [to_document(point) async for point in scroll_records(client, collection, filters, fields, limit=limit)]


async def retrieve_records(client, collection, ids, *, fields=True, opaque_ids=False):
    """Retrieve IDs in request order, using Haystack conversion for opaque document IDs."""
    started = time.monotonic()
    converted = [convert_id(value) for value in ids] if opaque_ids else list(ids)
    result = []
    try:
        for offset in range(0, len(converted), 128):
            batch = converted[offset:offset + 128]
            points = await client.retrieve(
                collection_name=collection, ids=batch, with_payload=fields, with_vectors=False,
            )
            by_id = {str(point.id).replace("-", ""): point for point in points}
            result.extend(by_id[str(point_id).replace("-", "")] for point_id in batch
                          if str(point_id).replace("-", "") in by_id)
    except Exception as error:
        _failure("retrieve", collection, started, error)
        raise
    logger.debug(
        "Qdrant operation=retrieve collection=%s requested=%d records=%d seconds=%.3f",
        collection, len(converted), len(result), time.monotonic() - started,
    )
    return result
