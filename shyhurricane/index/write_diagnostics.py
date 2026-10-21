"""Bounded diagnostics for document persistence failures."""

import logging
import time

from haystack.document_stores.types import DuplicatePolicy
from haystack_integrations.document_stores.qdrant.document_store import QdrantStoreError
from qdrant_client.http.exceptions import ResponseHandlingException

logger = logging.getLogger(__name__)


def write_document(store, collection, doc):
    """Write once, preserving failure propagation and avoiding document payload logging."""
    started = time.monotonic()
    try:
        store.write_documents([doc], policy=DuplicatePolicy.OVERWRITE)
    except Exception as error:
        cause = error
        seen = set()
        while id(cause) not in seen:
            seen.add(id(cause))
            nested = cause.__cause__ or cause.__context__
            if isinstance(cause, ResponseHandlingException):
                nested = cause.source
            if nested is None:
                break
            cause = nested
        logger.error(
            "Qdrant operation=write_documents collection=%s document_id=%s document_type=%s "
            "seconds=%.3f timeout=%s error=%s transport_error=%s outcome=failed",
            collection, doc.id, doc.meta.get("type"), time.monotonic() - started,
            store.timeout, type(error).__name__, type(cause).__name__,
            exc_info=not isinstance(error, (ResponseHandlingException, QdrantStoreError)),
        )
        raise
