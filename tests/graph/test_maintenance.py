import threading
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import maintenance
from shyhurricane.graph.maintenance import GraphMaintenance, migrate_cleanup


def migration_store(pages):
    store = MagicMock()
    store.timeouts.read = 30
    tx = store.connect.return_value.session.return_value.__enter__.return_value.begin_transaction.return_value
    tx = tx.__enter__.return_value
    marker = {"cursor": "", "complete": False}
    pages = iter(pages)

    def run(statement, **parameters):
        if "RETURN m.cursor" in statement:
            result = MagicMock()
            result.single.return_value = dict(marker)
            return result
        if "RETURN p.id" in statement:
            return next(pages)
        if "MATCH (m:GraphState" in statement:
            marker.update(cursor=parameters["after"], complete=parameters["complete"])
        return MagicMock()

    tx.run.side_effect = run
    return store, tx


def test_migration_advances_cursor_in_same_transaction_and_finishes(monkeypatch):
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    store, tx = migration_store([[{"id": f"{i:04}"} for i in range(500)], [{"id": "last"}]])
    assert migrate_cleanup(store, 20, threading.Event()) == 501
    updates = [call.kwargs for call in tx.run.call_args_list if "MATCH (m:GraphState" in call.args[0]]
    assert updates == [
        {"id": maintenance.MIGRATION_ID, "after": "0499", "complete": False},
        {"id": maintenance.MIGRATION_ID, "after": "last", "complete": True},
    ]
    session = store.connect.return_value.session.return_value.__enter__.return_value
    assert session.begin_transaction.call_count == 2
    session.begin_transaction.assert_called_with(timeout=20)


def test_migration_finished_empty_stopped_and_budget_exhausted(monkeypatch):
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    store, tx = migration_store([[]])
    assert migrate_cleanup(store, 60, threading.Event()) == 0
    assert tx.run.call_args.kwargs["complete"] is True
    tx.run.side_effect = None
    tx.run.return_value.single.return_value = {"complete": True}
    assert migrate_cleanup(store, 60, threading.Event()) == 0
    stop = threading.Event()
    stop.set()
    store.connect.reset_mock()
    assert migrate_cleanup(store, 60, stop) == 0
    assert migrate_cleanup(store, 0, threading.Event()) == 0
    store.connect.assert_not_called()


def test_migration_failure_rolls_back_and_batch_limit_is_bounded(monkeypatch):
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    store, tx = migration_store([[{"id": str(i)} for i in range(500)]] * 10)
    assert migrate_cleanup(store, 60, threading.Event()) == 5000
    store, tx = migration_store([[]])
    failure = RuntimeError("interrupted")
    tx.run.side_effect = failure
    with pytest.raises(RuntimeError, match="interrupted"):
        migrate_cleanup(store, 60, threading.Event())
    transaction = store.connect.return_value.session.return_value.__enter__.return_value.begin_transaction.return_value
    assert transaction.__exit__.call_args.args[1] is failure


def test_maintenance_backoff_resets_independently_and_preserves_readiness(monkeypatch, caplog):
    store = MagicMock()
    store.cleanup.return_value = {"selected": 1, "completed": 1, "deleted": 50}
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=RuntimeError("offline"))
    monkeypatch.setattr(maintenance, "migrate_cleanup", migrate)
    ready = MagicMock(return_value=True)
    worker = GraphMaintenance("location", ready)
    for delay in [60, 120, 240, 480, 900, 900]:
        now[0] = worker.next_attempt["migration"]
        assert worker.tick() == 60
        assert worker.next_attempt["migration"] == now[0] + delay
    assert store.cleanup.call_count == 6
    assert worker.failures == {"cleanup": 0, "migration": 6}
    ready.assert_not_called()
    migrate.side_effect = None
    migrate.return_value = 12
    now[0] = worker.next_attempt["migration"]
    assert worker.tick() == 60
    assert worker.failures == {"cleanup": 0, "migration": 0}
    store.cleanup.side_effect = RuntimeError("delete failed")
    now[0] += 60
    migration_calls = migrate.call_count
    assert worker.tick() == 60
    assert migrate.call_count == migration_calls + 1
    assert worker.failures == {"cleanup": 1, "migration": 0}
    assert "operation=cleanup" in caplog.text and "next_attempt_seconds=900" in caplog.text


def test_cleanup_keeps_running_while_migration_is_backed_off(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=RuntimeError("offline"))
    monkeypatch.setattr(maintenance, "migrate_cleanup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    worker.tick()
    now[0] = 60
    worker.tick()
    assert worker.next_attempt == {"cleanup": 120, "migration": 180}
    now[0] = 120
    assert worker.tick() == 60
    assert store.cleanup.call_count == 3 and migrate.call_count == 2


@pytest.mark.parametrize("code,shrinks", [
    ("Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration", True),
    ("Neo.TransientError.General.MemoryPoolOutOfMemoryError", True),
    ("Neo.ClientError.Statement.SyntaxError", False),
])
def test_migration_retries_smaller_batches_only_for_resource_limits(monkeypatch, code, shrinks):
    from neo4j.exceptions import Neo4jError

    monkeypatch.setattr(maintenance, "GraphStore", lambda location: MagicMock())
    now = [0.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: now[0])
    migrate = MagicMock(side_effect=Neo4jError._hydrate_neo4j(code=code, message="injected failure"))
    monkeypatch.setattr(maintenance, "migrate_cleanup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    worker.tick()
    assert migrate.call_args.kwargs["batch_size"] == 500
    assert worker.migration_batch_size == (250 if shrinks else 500)
    worker.migration_batch_size = 1
    now[0] = 60
    worker.tick()
    assert migrate.call_args.kwargs["batch_size"] == 1
    assert worker.migration_batch_size == 1


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
        calls.append(("migration", deadline))
        now[0] += 20
        return 500

    store.cleanup.side_effect = cleanup
    monkeypatch.setattr(maintenance, "migrate_cleanup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    assert worker.tick() == 40
    assert calls == [("cleanup", 30), ("migration", 100)]
    assert worker.migration_batch_size == 250


def test_shutdown_between_operations_skips_migration(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(maintenance, "GraphStore", lambda location: store)
    migrate = MagicMock()
    monkeypatch.setattr(maintenance, "migrate_cleanup", migrate)
    worker = GraphMaintenance("location", lambda: True)
    def cleanup(**kwargs):
        worker.stop_event.set()
        return {"selected": 0, "completed": 0, "deleted": 0}

    store.cleanup.side_effect = cleanup
    assert worker.tick() == 60
    assert worker.failures == {"cleanup": 0, "migration": 0}
    migrate.assert_not_called()


def test_migration_uses_reduced_page_size_without_skipping_cursor(monkeypatch):
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    store, tx = migration_store([[{"id": "a"}, {"id": "b"}], [{"id": "c"}]])
    assert migrate_cleanup(store, 30, threading.Event(), batch_size=2) == 3
    pages = [call.kwargs for call in tx.run.call_args_list if "RETURN p.id" in call.args[0]]
    assert pages == [{"after": "", "limit": 2}, {"after": "b", "limit": 2}]
    updates = [call.kwargs for call in tx.run.call_args_list if "MATCH (m:GraphState" in call.args[0]]
    assert [(row["after"], row["complete"]) for row in updates] == [("b", False), ("c", True)]


def test_migration_timeout_does_not_advance_committed_cursor(monkeypatch):
    from neo4j.exceptions import Neo4jError

    monkeypatch.setattr(maintenance.time, "monotonic", lambda: 0)
    store, tx = migration_store([[{"id": "a"}, {"id": "b"}]])
    original = tx.run.side_effect

    def timeout(statement, **parameters):
        if statement.startswith("UNWIND"):
            raise Neo4jError._hydrate_neo4j(
                code="Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration", message="slow HDD",
            )
        return original(statement, **parameters)

    tx.run.side_effect = timeout
    with pytest.raises(Neo4jError):
        migrate_cleanup(store, 30, threading.Event(), batch_size=2)
    assert not any("MATCH (m:GraphState" in call.args[0] for call in tx.run.call_args_list)
    transaction = store.connect.return_value.session.return_value.__enter__.return_value.begin_transaction.return_value
    assert transaction.__exit__.call_args.args[0] is not None


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
