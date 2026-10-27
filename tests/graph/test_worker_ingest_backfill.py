from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from haystack import Document

from shyhurricane.graph import backfill, worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.ingest import CaptureGraphEvents, GraphCaptureError
from shyhurricane.index.input_documents import IngestableRequestResponse
from shyhurricane.persistent_queue import get_persistent_queue


def test_ingest_captures_before_forwarding_and_is_durable(graph_paths, event):
    data = {**event()["data"], "response_rtt": None, "technologies": None, "forms": None}
    rr = IngestableRequestResponse(**data)
    tap = CaptureGraphEvents("db")
    assert tap.run([rr])["request_responses"] == [rr]
    queue = get_persistent_queue("db", "graph_queue")
    queued = queue.get(block=False)
    artifacts = ArtifactStore("db")
    assert artifacts.latest(rr.url)["id"] == queued["id"]
    queue.ack(queued)
    queue.close()
    artifacts.close()


def test_backfill_is_offline_and_resumable(graph_paths):
    doc = Document(id="doc", content='<a href="/next">next</a>', meta={"url": "https://example.com/", "timestamp": ""})
    store = SimpleNamespace(filter_documents=lambda: [doc])
    assert backfill.backfill("db", stores={"content": store}) == 1
    assert backfill.backfill("db", stores={"content": store}) == 0
    form = Document(id="form", content='[{"action":"/save","method":"POST"}]', meta={"url": "https://example.com/"})
    assert backfill.backfill("db", stores={"forms": SimpleNamespace(filter_documents=lambda: [form])}) == 1
    queue = get_persistent_queue("db", "graph_queue")
    assert queue.get(block=False)["backfill"] is True
    queue.close()


def test_backfill_streams_without_vectors_and_closes_client(graph_paths, monkeypatch):
    client = MagicMock()
    client.collection_exists.side_effect = [True, False]
    record = SimpleNamespace(id="id", payload={"content": "body", "meta": {"url": "https://example.com/"}})
    client.scroll.side_effect = [([record], "next"), ([], None)]
    monkeypatch.setattr(backfill, "QdrantClient", lambda **kwargs: client)
    monkeypatch.setattr(backfill, "qdrant_host_port", lambda db: ("localhost", 6333))
    assert len(list(backfill.StoredCollection("db", "content").filter_documents())) == 1
    assert not list(backfill.StoredCollection("db", "missing").filter_documents())
    assert all(call.kwargs["with_vectors"] is False for call in client.scroll.call_args_list)
    assert client.close.call_count == 2


def test_ingest_handoff_failure_is_retryable(graph_paths, monkeypatch):
    monkeypatch.setattr(
        "shyhurricane.graph.ingest.get_persistent_queue", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk"))
    )
    with pytest.raises(GraphCaptureError):
        CaptureGraphEvents("db").run([])


def test_ingest_artifact_failure_is_retryable(monkeypatch):
    monkeypatch.setattr(
        "shyhurricane.graph.ingest.ArtifactStore", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk"))
    )
    with pytest.raises(GraphCaptureError):
        CaptureGraphEvents("db").run([])


def test_stopped_worker_does_not_consume(graph_paths, monkeypatch):
    queue = MagicMock()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "GraphStore", MagicMock())
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: False)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue.get.assert_not_called()


def test_start_worker_and_backfill_command(monkeypatch, capsys, tmp_path):
    process = MagicMock()
    monkeypatch.setattr(worker.multiprocessing, "Process", lambda **kwargs: process)
    assert worker.start_graph_worker("db", "graph", object(), object(), False) is process
    process.start.assert_called_once()
    monkeypatch.setattr("sys.argv", ["backfill", "--data-dir", str(tmp_path)])
    monkeypatch.setattr(backfill, "backfill", lambda db: 5)
    backfill.main()
    assert "Queued 5" in capsys.readouterr().out
