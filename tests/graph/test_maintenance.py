from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import maintenance
from shyhurricane.graph.maintenance import GraphMaintenance


@pytest.fixture(autouse=True)
def lookup_migration(monkeypatch):
    monkeypatch.setattr(maintenance, "migrate_lookup", MagicMock(return_value=0))


def test_maintenance_backoff_resets_independently_and_preserves_readiness(monkeypatch, caplog):
    store = MagicMock()
    store.cleanup.return_value = {"selected": 1, "completed": 1, "deleted": 50}
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=RuntimeError("offline"))
    monkeypatch.setattr(maintenance, "migrate_lookup", migrate)
    ready = MagicMock(return_value=True)
    worker = GraphMaintenance("location", ready)
    for delay in [60, 120, 240, 480, 900, 900]:
        now[0] = worker.next_attempt["lookup"]
        assert worker.tick() == 60
        assert worker.next_attempt["lookup"] == now[0] + delay
    assert store.cleanup.call_count == 6
    assert worker.failures == {"cleanup": 0, "lookup": 6}
    ready.assert_not_called()
    migrate.side_effect = None
    migrate.return_value = 12
    now[0] = worker.next_attempt["lookup"]
    assert worker.tick() == 60
    assert worker.failures == {"cleanup": 0, "lookup": 0}
    store.cleanup.side_effect = RuntimeError("delete failed")
    now[0] += 60
    lookup_calls = migrate.call_count
    assert worker.tick() == 60
    assert migrate.call_count == lookup_calls + 1
    assert worker.failures == {"cleanup": 1, "lookup": 0}
    assert "operation=cleanup" in caplog.text and "next_attempt_seconds=900" in caplog.text


def test_cleanup_keeps_running_while_lookup_is_backed_off(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=RuntimeError("offline"))
    monkeypatch.setattr(maintenance, "migrate_lookup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    worker.tick()
    now[0] = 60
    worker.tick()
    assert worker.next_attempt == {"cleanup": 120, "lookup": 180}
    now[0] = 120
    assert worker.tick() == 60
    assert store.cleanup.call_count == 3 and migrate.call_count == 2


@pytest.mark.parametrize("code,shrinks", [
    ("Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration", True),
    ("Neo.TransientError.General.MemoryPoolOutOfMemoryError", True),
    ("Neo.ClientError.Statement.SyntaxError", False),
])
def test_lookup_retries_smaller_batches_only_for_resource_limits(monkeypatch, code, shrinks):
    from neo4j.exceptions import Neo4jError

    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=Neo4jError._hydrate_neo4j(code=code, message="injected failure"))
    monkeypatch.setattr(maintenance, "migrate_lookup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    worker.tick()
    assert migrate.call_args.kwargs["batch_size"] == 500
    assert worker.lookup_batch_size == (250 if shrinks else 500)
    worker.lookup_batch_size = 1
    now[0] = 60
    worker.tick()
    assert migrate.call_args.kwargs["batch_size"] == 1
    assert worker.lookup_batch_size == 1


def test_operations_receive_fresh_budgets_after_slow_commits(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    calls = []

    def cleanup(**kwargs):
        calls.append(("cleanup", kwargs["deadline"]))
        now[0] += 70  # A commit can exceed its cooperative budget.
        return {"selected": 1, "completed": 1, "deleted": 3}

    def migrate(store, deadline, stop_event, **kwargs):
        calls.append(("lookup", deadline))
        now[0] += 20
        return 500

    store.cleanup.side_effect = cleanup
    monkeypatch.setattr(maintenance, "migrate_lookup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    assert worker.tick() == 40
    assert calls == [("cleanup", 30), ("lookup", 100)]
    assert worker.lookup_batch_size == 250


def test_shutdown_between_operations_skips_lookup(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    migrate = MagicMock()
    monkeypatch.setattr(maintenance, "migrate_lookup", migrate)
    worker = GraphMaintenance("location", lambda: True)

    def cleanup(**kwargs):
        worker.stop_event.set()
        return {"selected": 0, "completed": 0, "deleted": 0}

    store.cleanup.side_effect = cleanup
    assert worker.tick() == 60
    assert worker.failures == {"cleanup": 0, "lookup": 0}
    migrate.assert_not_called()


@pytest.mark.parametrize("healthy", [True, False])
def test_maintenance_runs_independently_and_closes_driver(monkeypatch, healthy):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    worker = GraphMaintenance("location", lambda: healthy)
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.side_effect = [False, True]
    worker.tick = MagicMock(return_value=60)
    worker.run()
    assert worker.tick.call_count == int(healthy)
    worker.stop_event.wait.assert_called_once_with(60 if healthy else 1)
    store.close.assert_called_once()


def test_thread_start_close_and_shutdown_deadline(monkeypatch, caplog):
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    worker = GraphMaintenance("location", lambda: False)
    worker.thread = MagicMock()
    worker.start()
    worker.thread.start.assert_called_once()
    worker.thread.is_alive.return_value = False
    worker.close(0)
    assert worker.stop_event.is_set()
    worker.thread.join.assert_called_once_with(timeout=0)
    worker.thread.is_alive.return_value = True
    worker.close(0)
    assert "shutdown deadline" in caplog.text
