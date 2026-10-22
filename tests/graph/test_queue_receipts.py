"""Queue rows reflect publication outcomes, including durable continuation handoffs."""

import sqlite3
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import CypherSyntaxError, ServiceUnavailable
from persistqueue import SQLiteAckQueue

from shyhurricane.graph import worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.continuations import Continuations
from shyhurricane.graph.model import Projection
from shyhurricane.graph.queue_receipts import QueueReceipts
from shyhurricane.graph.scheduling import ReanalysisScheduler


def projection(current, *args, **kwargs):
    graph = Projection(current)
    graph.library_analysis = "summary"
    return graph


@pytest.mark.parametrize("failed", [False, True])
def test_receipts_survive_reopen_and_settle_by_id(tmp_path, failed):
    connection = sqlite3.connect(tmp_path / "artifacts.db")
    connection.execute("CREATE TABLE graph_continuations(id TEXT PRIMARY KEY,state TEXT)")
    connection.execute("INSERT INTO graph_continuations VALUES ('job','pending')")
    connection.commit()
    queue = SQLiteAckQueue(str(tmp_path / "queue"), auto_commit=True, auto_resume=False)
    queue.put({"id": "capture"})
    receipt = queue.get(raw=True)
    receipts = QueueReceipts(connection, queue)
    assert not receipts.contains("job")
    receipts.track("job", receipt)
    receipts.track("job", receipt)
    assert receipts.contains("job")
    assert receipt["pqid"] not in queue._unack_cache
    assert queue.unack_count() == 1 and queue.acked_count() == 0
    queue.close()
    queue = SQLiteAckQueue(str(tmp_path / "queue"), auto_commit=True, auto_resume=False)
    connection.execute("UPDATE graph_continuations SET state=?", ("failed" if failed else "done",))
    connection.commit()
    receipts = QueueReceipts(connection, queue)
    receipts.recover()
    assert queue.ack_failed_count() == int(failed)
    assert queue.acked_count() == int(not failed)
    assert not receipts.contains("job")
    receipts.recover()
    queue.close()
    connection.close()


def test_payload_only_queue_adapter_and_no_receipts():
    connection = sqlite3.connect(":memory:")
    queue = MagicMock()
    receipts = QueueReceipts(connection, queue)
    item = {"id": "capture"}
    receipts.track("job", item)
    assert receipts.contains("job")
    receipts.settle("job", failed=True)
    queue.ack_failed.assert_called_once_with(item)
    queue.ack.assert_not_called()
    receipts.settle("job", failed=False)
    assert not receipts.contains("job")
    connection.close()


@pytest.mark.parametrize("script", [False, True])
@pytest.mark.parametrize("stage", ["publish", "reconcile"])
@pytest.mark.parametrize("failure", [None, ServiceUnavailable("down"), CypherSyntaxError("bad query"),
                                  TimeoutError("deadline")])
def test_worker_marks_real_queue_rows_only_after_storage_outcome(
    graph_paths, event, monkeypatch, script, stage, failure
):
    capture = event(url="https://example.com/app.js" if script else "https://example.com/",
                    body="const x=1;" if script else "page",
                    mime="text/javascript" if script else "text/html")
    artifacts = ArtifactStore("db")
    artifacts.register(capture)
    artifacts.close()
    queue = SQLiteAckQueue(str(graph_paths / "actual-queue"), auto_commit=True, auto_resume=False)
    queue.put(capture)
    store = MagicMock()
    store.read.return_value = []
    published = []

    def publish(graph):
        assert queue.acked_count() == 0
        assert queue.unack_count() == 1
        published.append(graph.event["id"])
        if failure and stage == "publish":
            raise failure

    store.publish.side_effect = publish
    if failure and stage == "reconcile":
        def fail_reconcile(*args, **kwargs):
            raise failure

        if script:
            monkeypatch.setattr(Continuations, "reconcile", fail_reconcile)
        else:
            monkeypatch.setattr(worker, "complete_capture", fail_reconcile)
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **kw: queue)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *a, **kw: iter([queue.get(raw=True)]))
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr(worker, "extract", projection)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue = SQLiteAckQueue(str(graph_paths / "actual-queue"), auto_commit=True, auto_resume=False)
    assert len(published) == 1
    assert queue.acked_count() == int(failure is None)
    transient = isinstance(failure, ServiceUnavailable)
    assert queue.ack_failed_count() == int(failure is not None and not transient)
    assert queue.ready_count() == int(transient and not script)
    assert queue.unack_count() == int(transient and script)
    queue.close()


def test_running_managed_continuation_survives_restart_and_explicit_failed_retry(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url="https://example.com/a.js", body="x", mime="text/javascript"))
    queue_path = str(graph_paths / "actual-queue")
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    scheduler = ReanalysisScheduler(artifacts, queue)
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    receipt = queue.get(raw=True)
    claimed = scheduler.claim(receipt["data"])
    jobs = Continuations(artifacts)
    key = jobs.enqueue(claimed, receipt["data"], False)
    QueueReceipts(artifacts.connection, queue).track(key, receipt)
    queue.close()

    artifacts.close()
    store = MagicMock()
    store.read.return_value = []
    store.publish.side_effect = CypherSyntaxError("bad query after restart")
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **kw: queue)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *a, **kw: iter([queue.get(raw=True, block=False)]))
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr(worker, "extract", projection)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    assert queue.ack_failed_count() == 1 and queue.acked_count() == 0
    # Explicitly redeliver the failed row; no scheduler or continuation auto-retry is needed.
    queue.nack(id=receipt["pqid"])
    store.publish.side_effect = None
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    assert queue.acked_count() == 1 and queue.ack_failed_count() == 0
    assert store.publish.call_count == 2
    queue.close()


@pytest.mark.parametrize("stage", ["publish", "reconcile"])
def test_transient_continuation_recovers_automatically_after_restart(graph_paths, event, monkeypatch, stage):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url="https://example.com/a.js", body="x", mime="text/javascript"))
    queue_path = str(graph_paths / "retry-queue")
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    queue.put(capture)
    store = MagicMock()
    store.read.return_value = []
    if stage == "publish":
        store.publish.side_effect = [ServiceUnavailable("temporary outage"), None]
    else:
        monkeypatch.setattr(Continuations, "reconcile", MagicMock(side_effect=[ServiceUnavailable("outage"), True]))
    artifacts.close()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **kw: queue)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *a, **kw: iter([queue.get(raw=True, block=False)]))
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr(worker, "extract", projection)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    assert queue.acked_count() == queue.ack_failed_count() == 0
    assert queue.unack_count() == 1
    artifacts = ArtifactStore("db")
    assert artifacts.connection.execute("SELECT state,retries FROM graph_continuations").fetchone() == ("pending", 1)
    assert artifacts.connection.execute("SELECT status FROM work").fetchone()[0] == "pending"
    # Simulate expiry of the persisted retry deadline without a wall-clock sleep or manual queue retry.
    with artifacts.connection:
        artifacts.connection.execute("UPDATE graph_continuations SET next_attempt=0")
    artifacts.close()
    worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    assert queue.acked_count() == 1 and queue.ack_failed_count() == 0
    assert store.publish.call_count == (2 if stage == "publish" else 1)
    queue.close()
