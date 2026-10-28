"""Worker obligations survive unavailable dependencies and process interruptions."""

from contextlib import closing
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from qdrant_client.http import models as qm

import shyhurricane.investigation.worker as worker
from shyhurricane.investigation.storage import CorrelationStore
from tests.investigation.test_engine import Query


async def test_reconcile_is_vector_free_bounded_and_restartable():
    client = SimpleNamespace(
        scroll=AsyncMock(
            return_value=(
                [
                    qm.Record(id=1, payload={"id": "finding", "meta": {"url": "https://example.com/a"}}),
                    qm.Record(
                        id=2, payload={"meta": {"host": "example.com", "finding_metadata": {"severity": "high"}}}
                    ),
                    qm.Record(id=3, payload={}),
                ],
                4,
            )
        )
    )
    with closing(CorrelationStore("test")) as store:
        await worker.reconcile(store, client)
        assert store.setting("reconcile_offset") == 4
        assert store.status()["pending"] == 2
        assert client.scroll.call_args.kwargs["with_vectors"] is False
        assert client.scroll.call_args.kwargs["limit"] == 100
        client.scroll.return_value = ([], None)
        await worker.reconcile(store, client)
        assert client.scroll.call_args.kwargs["offset"] == 4
        assert store.setting("reconcile_complete")
        assert store.setting("last_reconciliation")
        await worker.reconcile(store, client)
        assert client.scroll.call_count == 2


def test_materialize_atomic_publish_and_failure_classes(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        assert not worker.materialize_one(store, Mock(), Mock(), 1)
        store.submit("finding", "https://example.com/a", {})
        monkeypatch.setattr(store, "neighbors", lambda *args: ([], True))
        assert worker.materialize_one(store, Mock(), Mock(), 1)
        result = store.read("example.com")["results"][0]
        assert result["finding_ids"] == ["finding"]
        while store._select_job(("derive", "hotspot")):
            assert worker.materialize_one(store, Mock(), Mock(), 1)
        monkeypatch.setattr(worker, "correlate", Mock(side_effect=TimeoutError()))
        assert worker.materialize_one(store, Mock(), Mock(), 2)
        assert store.status()["pending"] == 1
        store.connection.execute("UPDATE jobs SET due=0")
        store.connection.commit()
        monkeypatch.setattr(worker, "correlate", Mock(side_effect=ValueError()))
        assert worker.materialize_one(store, Mock(), Mock(), 2)
        assert store.status()["failed"] == 1


def test_graph_revision_and_process_entrypoints(monkeypatch):
    graph = Mock()
    graph.read.return_value = [{"revision": 5}]
    assert worker.graph_revision(graph) == 5
    graph.read.return_value = []
    assert worker.graph_revision(graph) == 0
    process = Mock()
    monkeypatch.setattr(worker.multiprocessing, "Process", Mock(return_value=process))
    assert worker.start_investigation_worker("db", "graph", "health", "stop") is process
    process.start.assert_called_once()
    assert process._shyhurricane_monitor_process_group
    monkeypatch.setattr(worker, "prepare_worker_process", Mock())
    monkeypatch.setattr(worker, "run_worker", AsyncMock())
    worker.investigation_worker("db", "graph", "health", "stop")
    worker.run_worker.assert_awaited_once_with("db", "graph", "health", "stop")


class Stop:
    def __init__(self, iterations):
        self.iterations = iterations
        self.checks = 0
        self.waits = []

    def is_set(self):
        self.checks += 1
        return self.checks > self.iterations

    def wait(self, seconds):
        self.waits.append(seconds)


@pytest.mark.parametrize(
    "healthy,worked,failed,waits",
    [
        (False, False, False, [1]),
        (True, False, False, [1]),
        (True, True, False, []),
        (True, False, True, [5]),
    ],
)
async def test_run_loop_health_idle_and_failure(monkeypatch, healthy, worked, failed, waits):
    import shyhurricane.db
    import shyhurricane.graph.artifacts

    store, graph, artifacts = Mock(), Mock(), Mock()
    client = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(worker, "CorrelationStore", lambda db: store)
    monkeypatch.setattr(worker, "GraphStore", lambda location: graph)
    monkeypatch.setattr(shyhurricane.db, "create_qdrant_client", AsyncMock(return_value=client))
    monkeypatch.setattr(shyhurricane.graph.artifacts, "ArtifactStore", lambda db: artifacts)
    monkeypatch.setattr(worker, "reconcile", AsyncMock(side_effect=ValueError() if failed else None))
    monkeypatch.setattr(worker, "graph_revision", lambda graph: 3)
    monkeypatch.setattr(worker, "materialize_one", Mock(return_value=worked))
    stop = Stop(1)
    await worker.run_worker("db", "graph", SimpleNamespace(is_set=lambda: healthy), stop)
    assert stop.waits == waits
    store.close.assert_called_once()
    graph.close.assert_called_once()
    artifacts.close.assert_called_once()
    client.close.assert_awaited_once()


async def test_initialization_failure_closes_partial_resources(monkeypatch):
    import shyhurricane.db

    store, graph = Mock(), Mock()
    monkeypatch.setattr(worker, "CorrelationStore", lambda db: store)
    monkeypatch.setattr(worker, "GraphStore", lambda location: graph)
    monkeypatch.setattr(shyhurricane.db, "create_qdrant_client", AsyncMock(side_effect=RuntimeError()))
    with pytest.raises(RuntimeError):
        await worker.run_worker("db", "graph", Mock(), Stop(0))
    store.close.assert_called_once()
    graph.close.assert_called_once()
