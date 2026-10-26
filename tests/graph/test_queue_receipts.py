"""Queue rows reflect publication outcomes, including durable continuation handoffs."""

import sqlite3
from threading import Event
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import CypherSyntaxError, ServiceUnavailable
from persistqueue import SQLiteAckQueue

from shyhurricane.graph import epochs, worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.epochs import epoch_status
from shyhurricane.graph.model import Projection
from shyhurricane.graph.queue_receipts import QueueReceipts


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
@pytest.mark.parametrize("stage", ["structural", "links"])
@pytest.mark.parametrize("failure", [None, ServiceUnavailable("down"), CypherSyntaxError("bad query"),
                                  TimeoutError("deadline")])
def test_worker_marks_real_queue_rows_only_after_epoch_outcome(
    graph_paths, event, monkeypatch, script, stage, failure
):
    capture = event(url="https://example.com/app.js" if script else "https://example.com/",
                    body="const x=1;" if script else "page",
                    mime="text/javascript" if script else "text/html")
    queue_path = str(graph_paths / "actual-queue")
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    queue.put(capture)
    store = MagicMock()
    store.read.return_value = []
    attempts = []

    def publish(kind, graph):
        assert queue.acked_count() == 0
        assert queue.unack_count() == 1
        attempts.append(kind)
        if failure and kind == stage:
            raise failure
        return True

    monkeypatch.setattr(epochs.GraphPublisher, "publish", lambda self, graph: publish("structural", graph))
    monkeypatch.setattr(epochs.LinkPublisher, "publish", lambda self, graph: publish("links", graph))
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "Epochs", lambda artifacts, database, **kw: epochs.Epochs(artifacts, database))
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **kw: queue)

    def deliveries(*args, **kwargs):
        yield queue.get(raw=True, block=False)
        yield from ({"graph_epoch": True} for _ in range(30))

    monkeypatch.setattr(worker, "persistent_queue_get", deliveries)
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr(epochs, "extract", projection)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)
    worker.graph_worker("db", "graph", MagicMock(), Event(), False)
    queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
    transient = isinstance(failure, ServiceUnavailable)
    assert queue.acked_count() == int(failure is None)
    assert queue.ack_failed_count() == int(failure is not None and not transient)
    assert queue.unack_count() == int(transient)
    assert len(attempts) == (2 if stage == "links" or failure is None else 1)
    if failure:
        artifacts = ArtifactStore("db")
        status = epoch_status(artifacts.connection)
        assert status["phase"] == (stage if transient else "done")
        if transient:
            with artifacts.connection:
                artifacts.connection.execute("UPDATE graph_epochs SET next_attempt=0")
        else:
            failed = queue._getter.execute("SELECT _id FROM ack_queue_default WHERE status=9").fetchone()[0]
            queue.nack(id=failed)
        artifacts.close()
        # Restart recovery redelivers the processing row or the explicitly retried failure.
        queue.resume_unack_tasks()
        failure = None
        worker.graph_worker("db", "graph", MagicMock(), Event(), False)
        queue = SQLiteAckQueue(queue_path, auto_commit=True, auto_resume=False)
        assert queue.acked_count() == 1 and queue.ack_failed_count() == queue.unack_count() == 0
    queue.close()
