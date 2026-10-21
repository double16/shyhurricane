"""Write failures remain visible and propagate without retries."""

import logging
from unittest.mock import Mock

import httpx
import pytest
from haystack import Document
from qdrant_client.http.exceptions import ResponseHandlingException

from shyhurricane.index.web_resources_pipeline import IngestMultiStore
from shyhurricane.index.write_diagnostics import write_document


def test_successful_write():
    store = Mock(timeout=5)
    doc = Document(content="secret", id="id")
    write_document(store, "content", doc)
    assert store.write_documents.call_count == 1


@pytest.mark.parametrize("transport", [True, False])
def test_failed_write_preserves_exception_and_context(transport, caplog):
    cause = httpx.ReadTimeout("secret body and https://user:pass@example.com/?token=secret")
    error = ResponseHandlingException(cause) if transport else RuntimeError("unexpected")
    error.__cause__ = cause
    store = Mock(timeout=5)
    store.write_documents.side_effect = error
    doc = Document(content="private contents", id="failed-id", meta={"type": "content"})
    with caplog.at_level(logging.ERROR), pytest.raises(type(error)) as raised:
        write_document(store, "content", doc)
    assert raised.value is error
    assert store.write_documents.call_count == 1
    record = caplog.records[-1]
    assert bool(record.exc_info) is not transport
    message = record.getMessage()
    for expected in ["collection=content", "document_id=failed-id", "timeout=5", "transport_error=ReadTimeout"]:
        assert expected in message
    assert "private contents" not in message and "secret" not in message


def test_partial_chunk_recovery_is_per_collection_and_bounded():
    docs = [Document(content="x", id=str(i)) for i in range(205)]
    first = Mock()
    first.get_documents_by_id.side_effect = lambda ids: [doc for doc in docs[:102] if doc.id in ids]
    second = Mock()
    second.get_documents_by_id.return_value = []
    writer = IngestMultiStore({"first": first, "second": second})
    assert writer.missing_documents("first", docs) == docs[102:]
    assert writer.missing_documents("second", docs) == docs
    assert [len(call.args[0]) for call in first.get_documents_by_id.call_args_list] == [100, 100, 5]
    first.get_documents_by_id.side_effect = lambda ids: [doc for doc in docs if doc.id in ids]
    assert writer.missing_documents("first", docs) == []
    assert writer.missing_documents("first", []) == []
    with pytest.raises(KeyError):
        writer.missing_documents("missing", docs)


def test_cyclic_exception_context_does_not_hang(caplog):
    error = RuntimeError("cycle")
    error.__cause__ = error
    store = Mock(timeout=None)
    store.write_documents.side_effect = error
    with pytest.raises(RuntimeError):
        write_document(store, "content", Document(content="x"))
    assert "transport_error=RuntimeError" in caplog.text
