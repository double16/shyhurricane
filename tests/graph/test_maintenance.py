from contextlib import closing
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


def test_inventory_reclamation_has_independent_schedule_and_retries(monkeypatch):
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    repair = MagicMock()
    repair.step.return_value = False
    monkeypatch.setattr(maintenance, "InventoryCleanup", lambda *args: repair)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    worker = GraphMaintenance("location", lambda: True, artifact_db="db")
    worker.inventory_schedule = lambda now: ("idle", 1)
    worker.tick()
    repair.step.assert_called_once_with(deadline=2)
    assert worker.next_attempt["inventory"] == 60
    now[0] = 60
    repair.step.side_effect = RuntimeError("locked")
    worker.tick()
    assert worker.failures["inventory"] == 1
    now[0] = 120
    repair.step.side_effect = None
    repair.step.return_value = False
    worker.tick()
    assert worker.failures["inventory"] == 0


def test_pending_storage_work_retries_promptly_without_failure_backoff(monkeypatch):
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    repair = MagicMock()
    repair.step.return_value = False
    storage = MagicMock()
    storage.root = __import__("pathlib").Path("/tmp/test-graph")
    storage.tick.return_value = {"processed": 500, "pending": True}
    monkeypatch.setattr(maintenance, "InventoryCleanup", lambda *args: repair)
    monkeypatch.setattr(maintenance, "StorageMaintenance", lambda db: storage)
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    worker = GraphMaintenance("location", lambda: True, artifact_db="db")
    assert worker.tick() == 1
    assert worker.next_attempt["storage"] == 1
    assert worker.failures["storage"] == 0


def test_storage_deferral_resets_failure_streak_and_retries(monkeypatch):
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    monkeypatch.setattr(maintenance, "InventoryCleanup", lambda *args: MagicMock())
    storage = MagicMock()
    storage.root = __import__("pathlib").Path("/tmp/test-graph")
    storage.tick.return_value = {"processed": 64, "pending": False, "deferred": True}
    monkeypatch.setattr(maintenance, "StorageMaintenance", lambda db: storage)
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    worker = GraphMaintenance("location", lambda: True, artifact_db="db")
    worker.failures["storage"] = 3
    assert worker.tick() == 1
    assert worker.failures["storage"] == 0
    worker.next_attempt["storage"] = 0
    assert worker.tick() == 1
    storage.tick.side_effect = RuntimeError("real failure")
    worker.next_attempt["storage"] = 0
    worker.tick()
    assert worker.failures["storage"] == 1
    assert worker.next_attempt["storage"] == 60


def test_storage_backoff_schedule_skips_early_attempts(monkeypatch):
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    monkeypatch.setattr(maintenance, "InventoryCleanup", lambda *args: MagicMock())
    storage = MagicMock()
    storage.root = __import__("pathlib").Path("/tmp/test-graph")
    storage.tick.return_value = {
        "processed": 0, "pending": True, "deferred": True, "next_attempt_seconds": 30,
    }
    monkeypatch.setattr(maintenance, "StorageMaintenance", lambda db: storage)
    now = [0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    worker = GraphMaintenance("location", lambda: True, artifact_db="db")
    worker.tick()
    assert worker.next_attempt["storage"] == 30
    now[0] = 29
    worker.tick()
    assert storage.tick.call_count == 1
    now[0] = 30
    worker.tick()
    assert storage.tick.call_count == 2
    assert worker.failures["storage"] == 0


@pytest.mark.parametrize("phase,elapsed,disk,expected", [
    ("references", None, {}, "fallback"),
    ("references", 60, {}, "active_epoch"),
    ("references", 1800, {}, "fallback"),
    ("done", 60, {}, "idle"),
    ("failed", 60, {}, "idle"),
    ("references", 60, {"state": "paused", "error": None}, "disk_pressure"),
    ("references", 60, {"state": "paused", "error": "unavailable"}, "active_epoch"),
])
def test_inventory_policy(tmp_path, monkeypatch, phase, elapsed, disk, expected):
    import sqlite3
    from types import SimpleNamespace
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    worker = GraphMaintenance("location", lambda: True, disk_snapshot=lambda: disk)
    worker.storage_maintenance = SimpleNamespace(root=tmp_path)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection, connection:
        connection.execute("CREATE TABLE graph_epochs (id INTEGER PRIMARY KEY,phase TEXT)")
        connection.execute("INSERT INTO graph_epochs (phase) VALUES (?)", (phase,))
    worker.inventory_last_pass = None if elapsed is None else 0
    assert worker.inventory_schedule(elapsed or 0)[0] == expected


def test_inventory_lock_timeout_yields_without_failure_backoff(monkeypatch):
    from neo4j.exceptions import Neo4jError

    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    worker = GraphMaintenance("location", lambda: True)
    worker.storage_maintenance = MagicMock()
    worker.storage_maintenance.tick.return_value = {"pending": False}
    worker.inventory_cleanup = MagicMock()
    worker.inventory_cleanup.step.side_effect = Neo4jError._hydrate_neo4j(
        code="Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration", message="busy",
    )
    worker.inventory_schedule = lambda now: ("disk_pressure", 5)
    worker.next_attempt["inventory"] = 0
    worker.failures["inventory"] = 0
    worker.tick()
    assert worker.next_attempt["inventory"] == 5
    assert worker.failures["inventory"] == 0



def test_completed_epoch_is_detected_even_if_next_epoch_is_active(tmp_path, monkeypatch):
    import sqlite3
    from types import SimpleNamespace

    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    worker = GraphMaintenance("location", lambda: True)
    worker.storage_maintenance = SimpleNamespace(root=tmp_path)
    worker.inventory_last_pass = 0
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection, connection:
        connection.execute("CREATE TABLE graph_epochs (id INTEGER PRIMARY KEY,phase TEXT)")
        connection.execute("INSERT INTO graph_epochs VALUES (1,'references')")
    assert worker.inventory_schedule(60)[0] == "active_epoch"
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection, connection:
        connection.execute("UPDATE graph_epochs SET phase='done'")
        connection.execute("INSERT INTO graph_epochs VALUES (2,'references')")
    assert worker.inventory_schedule(120)[0] == "epoch_complete"
    assert worker.inventory_schedule(121)[0] == "active_epoch"
