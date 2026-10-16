from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from haystack import Document
from neo4j.exceptions import CypherSyntaxError, ServiceUnavailable, TransientError

from shyhurricane.graph import backfill, worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.ingest import CaptureGraphEvents, GraphCaptureError
from shyhurricane.graph.publication import PublicationConflict, PublicationMemoryError
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


@pytest.mark.parametrize(
    "failure",
    [
        None,
        ServiceUnavailable("down"),
        ValueError("bad input"),
        CypherSyntaxError("syntax"),
        TransientError("retry"),
        PublicationConflict("race"),
        PublicationMemoryError("budget"),
    ],
)
def test_worker_commit_retry_and_retained_failures(graph_paths, event, monkeypatch, failure):
    capture = event()
    dependent = event(url="https://example.com/other")
    artifacts = ArtifactStore("db")
    artifacts.register(capture)
    artifacts.register(dependent)
    artifacts.references(dependent["id"], [capture["data"]["url"]])
    artifacts.close()
    queue = MagicMock()
    store = MagicMock()
    if failure:
        store.publish.side_effect = failure
    health = MagicMock()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *args, **kwargs: iter([capture]))
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", MagicMock(side_effect=[True, True]))
    worker.graph_worker("db", "bolt://test", health, MagicMock(), False)
    if failure is None:
        queue.ack.assert_called_once_with(capture)
        assert "reanalysis_ticket" in queue.put.call_args.args[0]
    elif isinstance(failure, PublicationConflict):
        queue.nack.assert_called_once_with(capture)
        health.clear.assert_not_called()
    elif isinstance(failure, (ServiceUnavailable, TransientError)):
        queue.nack.assert_called_once_with(capture)
        health.clear.assert_called_once()
    else:
        queue.ack_failed.assert_called_once_with(capture)
        health.clear.assert_not_called()
    store.close.assert_called()
    queue.close.assert_called_once()


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


def test_new_document_reconciles_existing_script_dependencies(graph_paths, event, monkeypatch):
    page = event(body='<script src="/entry.js"></script><a href="/page">self</a>')
    script = event(url="https://example.com/entry.js", mime="text/javascript")
    artifacts = ArtifactStore("db")
    artifacts.register(page)
    artifacts.register(script)
    artifacts.close()
    queue = MagicMock()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *args, **kwargs: iter([page]))
    monkeypatch.setattr(worker, "GraphStore", MagicMock())
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queued = [call.args[0] for call in queue.put.call_args_list]
    assert len(queued) == 1
    assert queued[0]["id"] == script["id"] and queued[0]["reanalysis_ticket"]
    artifacts = ArtifactStore("db")
    scheduler = worker.ReanalysisScheduler(artifacts, queue)
    assert scheduler.claim(queued[0])["reconcile_chain"] == [page["id"]]
    artifacts.close()


def test_worker_reconciliation_map_and_health_races(graph_paths, event, monkeypatch):
    capture = event(url="https://example.com/a.js.map", body="{}", mime="application/json")
    queue = MagicMock()
    health = MagicMock()
    health.is_set.side_effect = [False, True, True]
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(
        worker, "persistent_queue_get", lambda *args, **kwargs: iter([capture, capture, {**capture, "reconcile": True}])
    )
    monkeypatch.setattr(worker, "GraphStore", MagicMock())
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "graph", health, MagicMock(), False)
    queue.nack.assert_called_once_with(capture)
    assert queue.ack.call_count == 2


def test_start_worker_and_backfill_command(monkeypatch, capsys, tmp_path):
    process = MagicMock()
    monkeypatch.setattr(worker.multiprocessing, "Process", lambda **kwargs: process)
    assert worker.start_graph_worker("db", "graph", object(), object(), False) is process
    process.start.assert_called_once()
    monkeypatch.setattr("sys.argv", ["backfill", "--data-dir", str(tmp_path)])
    monkeypatch.setattr(backfill, "backfill", lambda db: 5)
    backfill.main()
    assert "Queued 5" in capsys.readouterr().out


@pytest.mark.parametrize(
    "failure",
    [
        None,
        ServiceUnavailable("down"),
        ValueError("bad input"),
        CypherSyntaxError("bad"),
        TransientError("retry"),
        PublicationConflict("race"),
        PublicationMemoryError("budget"),
    ],
)
def test_managed_ticket_success_retry_failure_and_obsolete_delivery(graph_paths, event, monkeypatch, failure):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    queue = MagicMock()
    scheduler = worker.ReanalysisScheduler(artifacts, queue)
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    item = queue.put.call_args.args[0]
    artifacts.close()
    store = MagicMock()
    store.publish.side_effect = failure
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    items = [item] if failure else [item, item]
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *args, **kwargs: iter(items))
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    store.publish.assert_called_once()
    artifacts = ArtifactStore("db")
    state = artifacts.connection.execute("SELECT state FROM reanalysis").fetchone()[0]
    artifacts.close()
    if isinstance(failure, (ServiceUnavailable, TransientError, PublicationConflict)):
        queue.nack.assert_called_once_with(item)
        assert state == "pending"
    elif failure:
        queue.ack_failed.assert_called_once_with(item)
        assert state == "done"
    else:
        assert queue.ack.call_count == 2
        assert state == "done"


def test_scheduler_startup_failure_is_logged_and_resources_close(graph_paths, monkeypatch, caplog):
    queue, store, scheduler = MagicMock(), MagicMock(), MagicMock()
    scheduler.recover.side_effect = OSError("delivery unavailable")
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr(worker, "ReanalysisScheduler", lambda *args: scheduler)
    with pytest.raises(OSError, match="delivery unavailable"):
        worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    assert "durable graph work retained for startup recovery" in caplog.text
    queue.close.assert_called_once()
    store.close.assert_called_once()


def test_explicit_zero_budget_stops_even_when_merged_chain_is_empty(graph_paths, event, monkeypatch):
    page = event(body='<script src="/entry.js"></script>')
    artifacts = ArtifactStore("db")
    artifacts.register(page)
    artifacts.register(event(url="https://example.com/entry.js", mime="text/javascript"))
    artifacts.close()
    queue, store = MagicMock(), MagicMock()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr(
        worker,
        "persistent_queue_get",
        lambda *args, **kwargs: iter([{**page, "reconcile": True, "reconcile_chain": [], "reconcile_remaining": 0}]),
    )
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    store.publish.assert_called_once()
    queue.put.assert_not_called()
