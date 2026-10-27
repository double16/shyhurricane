"""Incremental reference accounting, bounded work, and restart/concurrency invariants."""

import json
import sqlite3
import threading
import time
from contextlib import closing

import pytest

from shyhurricane.graph import storage_accounting
from shyhurricane.graph.blob_store import BlobStore, initialize
from shyhurricane.graph.storage_maintenance import StorageMaintenance


@pytest.fixture
def store(tmp_path):
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        yield BlobStore(connection)


def drain(store, *, budget=10**9, batch=64):
    for _ in range(10000):
        with store.connection:
            result = store.maintain(budget=budget, batch=batch)
        if not result["pending"]:
            return
    pytest.fail("maintenance did not converge")


def oracle(store):
    """Independent full traversal is allowed in tests, never in normal maintenance."""
    connection = store.connection
    edges = {}
    for parent, child in connection.execute("SELECT parent,child FROM graph_edges"):
        edges.setdefault(parent, set()).add(child)

    def closure(roots):
        seen, work = set(), list(roots)
        while work:
            node = work.pop()
            if node not in seen:
                seen.add(node)
                work.extend(edges.get(node, ()))
        return seen

    retained = closure(row[0] for row in connection.execute("SELECT DISTINCT ref FROM graph_object_owners"))
    cached = closure(row[0] for row in connection.execute("SELECT DISTINCT ref FROM graph_cache"))
    nodes = dict(connection.execute("SELECT id,digest FROM graph_nodes"))
    retained_blobs = {nodes[node] for node in retained}
    cached_blobs = {nodes[node] for node in cached} - retained_blobs
    blobs = {
        digest: (size, len(payload))
        for digest, size, payload in connection.execute("SELECT digest,size,payload FROM graph_blobs")
    }
    result = store.statistics()
    assert result["logical_payload_bytes"] == sum(v[0] for v in blobs.values())
    assert result["stored_payload_bytes"] == sum(v[1] for v in blobs.values())
    assert result["retained_bytes"] == sum(blobs[key][1] for key in retained_blobs)
    assert result["cache_bytes"] == sum(blobs[key][1] for key in cached_blobs)
    for key, owned, caching in connection.execute("SELECT id,retained,cached FROM graph_nodes"):
        assert bool(owned) == (key in retained)
        assert bool(caching) == (key in cached)
    assert not result["accounting_pending"]


def test_immutable_references_and_replacement_preserve_old_values(store):
    with store.connection:
        first = store.put("same-key", {"body": "first"})
        second = store.put("same-key", {"body": "second"})
        same = store.put("different-key", {"body": "first"})
    assert first == same and first != second
    assert store.read(first) == {"body": "first"}
    assert store.read(second) == {"body": "second"}
    with store.connection:
        store.own("retained", first)
        store.own("retained", second)
    drain(store)
    oracle(store)


def test_shared_text_multiple_roots_and_nested_classification(store):
    body = "shared text" * 2000
    with store.connection:
        child = store.put("child", {"body": body}, cache=True)
        parent = store.put("parent", {"nested": child, "body": body}, cache=True)
        store.own("first", parent)
        store.own("second", parent)
    assert store.statistics()["accounting_pending"]
    drain(store, batch=1)
    oracle(store)
    assert store.statistics()["cache_bytes"] == 0
    with store.connection:
        store.own("first", None)
    drain(store)
    oracle(store)
    with store.connection:
        store.own("second", None)
    drain(store)
    oracle(store)
    assert store.statistics()["cache_bytes"] > 0
    with store.connection:
        store.connection.execute("UPDATE graph_nodes SET created=0")
    drain(store, budget=0)
    oracle(store)
    assert store.connection.execute("SELECT count(*) FROM graph_blobs").fetchone() == (0,)


def test_classification_changes_coalesce_without_double_counting(store):
    with store.connection:
        child = store.put("child", {"body": "retained" * 1000})
        parent = store.put("parent", {"child": child})
        store.own("root", parent)
        store.own("root", None)
        store.own("root", parent)
    drain(store, batch=1)
    oracle(store)
    with store.connection:
        store.own("root", None)
        store.own("root", parent)
    drain(store, batch=1)
    oracle(store)
    with store.connection:
        store.delete(parent)  # owned artifacts cannot be retired
    assert store.exists(parent)
    with pytest.raises(sqlite3.IntegrityError), store.connection:
        store.own("root", "a:missing")
    with pytest.raises(sqlite3.IntegrityError), store.connection:
        store.connection.execute("UPDATE graph_object_owners SET ref='a:missing' WHERE owner='root'")
    oracle(store)


def test_high_fanout_restarts_from_committed_cursor(store, tmp_path):
    with store.connection:
        children = [store.put(f"child-{i}", {"number": i}) for i in range(700)]
        parent = store.put("parent", {"children": children})
        store.own("root", parent)
    with store.connection:
        result = store.maintain(batch=64)
    assert result["processed"] == 64 and result["pending"]
    cursor = store.connection.execute(
        "SELECT after_child FROM graph_storage_work WHERE parent=?", (parent,)
    ).fetchone()[0]
    assert cursor
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as reopened:
        replacement = BlobStore(reopened)
        assert reopened.execute("SELECT after_child FROM graph_storage_work WHERE parent=?", (parent,)).fetchone() == (
            cursor,
        )
        drain(replacement)
        oracle(replacement)
        with reopened:
            replacement.own("root", None)
            replacement.delete(parent)
            reopened.execute("UPDATE graph_nodes SET created=0")
        with reopened:
            partial = replacement.maintain(batch=64)
        assert partial["processed"] == 64 and partial["pending"]
        drain(replacement)
        assert reopened.execute("SELECT count(*) FROM graph_nodes").fetchone() == (0,)
        oracle(replacement)


def test_concurrent_reader_keeps_complete_blob_snapshot(store, tmp_path, monkeypatch):
    value = {"body": "shared body" * 5000}
    with store.connection:
        reference = store.put("capture", value)
    ready, finished = threading.Event(), threading.Event()
    raw = store._raw

    def pause(digest, limit):
        data = raw(digest, limit)
        if not ready.is_set():
            ready.set()
            assert finished.wait(10)
        return data

    monkeypatch.setattr(store, "_raw", pause)
    failures = []

    def writer():
        try:
            assert ready.wait(10)
            with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
                other = BlobStore(connection)
                with connection:
                    other.delete(reference)
                drain(other)
                assert not other.exists(reference)
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    thread = threading.Thread(target=writer)
    thread.start()
    assert store.read(reference) == value
    thread.join(10)
    assert not failures
    with pytest.raises(FileNotFoundError):
        store.read(reference)


def test_retiring_artifact_and_text_can_be_resurrected_safely(store):
    value = {"body": "shared body" * 1000}
    with store.connection:
        ref = store.put("first", value)
        store.delete(ref)
    assert not store.exists(ref)
    with store.connection:
        same = store.put("second", value)
        store.own("root", same)
    assert same == ref
    drain(store)
    assert store.read(ref) == value
    oracle(store)


def test_statistics_use_only_counters_and_indexed_maintenance_queries(store):
    statements = []
    store.connection.set_trace_callback(statements.append)
    store.statistics()
    assert len(statements) <= 5
    assert not any("graph_object_owners" in query or "RECURSIVE" in query for query in statements)
    store.connection.set_trace_callback(None)
    for query in [
        "SELECT id FROM graph_nodes INDEXED BY graph_node_unused WHERE owners=0 AND caches=0 "
        "AND incoming=0 AND retiring=0 AND created<0 ORDER BY created,id LIMIT 1",
        "SELECT digest FROM graph_blob_usage INDEXED BY graph_blob_unused WHERE node_refs=0 LIMIT 1",
    ]:
        plan = store.connection.execute("EXPLAIN QUERY PLAN " + query).fetchall()
        assert any("SEARCH" in row[3] for row in plan)
        assert not any("SCAN " in row[3] for row in plan)


def test_deadline_yields_keep_committed_batches_and_reclamation_runs(store, tmp_path, monkeypatch, caplog):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    with store.connection:
        for index in range(400):
            store.put(str(index), {"body": str(index)}, cache=True)
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    real_maintain = BlobStore.maintain
    calls = []
    interrupted = sqlite3.OperationalError("interrupted")
    interrupted.sqlite_errorcode = sqlite3.SQLITE_INTERRUPT

    def partial(self, **kwargs):
        calls.append(kwargs["batch"])
        if len(calls) == 2:
            # Active sub-batch must roll back, while the first 64 items stay committed.
            self.connection.execute("DELETE FROM graph_cache")
            monkeypatch.setattr(storage_maintenance, "PASS_SECONDS", 0)
            stop.set()
            raise interrupted
        return real_maintain(self, budget=0, **kwargs)

    monkeypatch.setattr(BlobStore, "maintain", partial)
    stop = threading.Event()
    result = StorageMaintenance("db").tick(stop)
    assert result["processed"] == 64 and result["pending"]
    assert len(calls) == 2 and all(count <= 64 for count in calls)
    assert store.connection.execute("SELECT count(*) FROM graph_cache").fetchone()[0] > 0
    assert "failed" not in caplog.text
    monkeypatch.setattr(BlobStore, "maintain", real_maintain)
    stop.clear()
    monkeypatch.setattr(storage_maintenance, "PASS_SECONDS", 2)
    assert StorageMaintenance("db").tick(stop)["processed"] > 0


def test_missing_deadline_database_and_empty_work(store, tmp_path, monkeypatch):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path / "missing")
    assert StorageMaintenance("db").tick(threading.Event()) == {
        "processed": 0, "pending": False, "deferred": False,
    }
    with store.connection:
        assert store.maintain() == {"processed": 0, "pending": False}
    assert not storage_accounting.pending(store.connection, 0)


def test_scale_600000_owners_keeps_statistics_and_cleanup_bounded(tmp_path, monkeypatch):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA cache_size=-65536")
        store = BlobStore(connection)
        shared = "shared complete source " * 2000
        started = time.perf_counter()
        with connection:
            roots = [store.put(str(index), {"owned": index, "body": shared}) for index in range(100)]
            connection.execute("CREATE TEMP TABLE scale_roots(n INTEGER PRIMARY KEY,ref TEXT)")
            connection.executemany("INSERT INTO scale_roots VALUES (?,?)", enumerate(roots))
            connection.execute(
                "WITH RECURSIVE seq(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM seq WHERE i<599999) "
                "INSERT INTO graph_object_owners SELECT 'owner-'||i,"
                "(SELECT ref FROM scale_roots WHERE n=i%100) FROM seq"
            )
            for index in range(500):
                store.put(f"cache-{index}", {"cached": index, "body": shared, "dependency": roots[0]}, cache=True)
        population_seconds = time.perf_counter() - started
        with connection:
            connection.execute("UPDATE graph_nodes SET created=0")
        drain(store)
        oracle(store)
        statements, instructions = [], [0]
        connection.set_trace_callback(statements.append)

        def count_instructions():
            instructions[0] += 1
            return int(instructions[0] > 10000)

        connection.set_progress_handler(count_instructions, 1)
        started = time.perf_counter()
        statistics = store.statistics()
        statistics_seconds = time.perf_counter() - started
        connection.set_progress_handler(None, 0)
        connection.set_trace_callback(None)
        assert len(statements) <= 5 and instructions[0] <= 10000
        assert all("graph_object_owners" not in query and "RECURSIVE" not in query for query in statements)
        assert statistics["cache_bytes"] > 0
        passes, durations = 0, []
        while True:
            started = time.perf_counter()
            result = StorageMaintenance("db").tick(threading.Event())
            durations.append(time.perf_counter() - started)
            passes += 1
            assert 0 < result["processed"] <= 500
            if not result["pending"]:
                break
            assert passes < 100
        assert connection.execute("SELECT count(*) FROM graph_object_owners").fetchone() == (600000,)
        assert connection.execute("SELECT count(*) FROM graph_cache").fetchone() == (0,)
        assert all(store.exists(root) for root in roots)
        oracle(store)
        assert store.statistics()["cache_bytes"] == 0
        print(
            json.dumps(
                {
                    "owners": 600000,
                    "cache_entries": 500,
                    "population_seconds": population_seconds,
                    "statistics_seconds": statistics_seconds,
                    "statistics_vm_instructions": instructions[0],
                    "maintenance_passes": passes,
                    "max_pass_seconds": max(durations),
                }
            )
        )


@pytest.mark.parametrize("code", [None, sqlite3.SQLITE_INTERRUPT, sqlite3.SQLITE_ERROR])
def test_reclamation_has_independent_budget_and_preserves_real_errors(store, tmp_path, monkeypatch, code):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    monkeypatch.setattr(storage_maintenance, "PASS_ITEMS", 0)
    connect = sqlite3.connect
    seen = []

    class Connection:
        def __init__(self, *args, **kwargs):
            self.db = connect(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.db, name)

        def execute(self, sql, *args):
            seen.append(sql)
            if "incremental_vacuum" in sql and code is not None:
                error = sqlite3.OperationalError("injected reclamation failure")
                error.sqlite_errorcode = code
                raise error
            return self.db.execute(sql, *args)

    monkeypatch.setattr(storage_maintenance.sqlite3, "connect", Connection)
    if code == sqlite3.SQLITE_ERROR:
        with pytest.raises(sqlite3.OperationalError):
            StorageMaintenance("db").tick(threading.Event())
    else:
        assert StorageMaintenance("db").tick(threading.Event())["processed"] == 0
    assert any("incremental_vacuum" in sql for sql in seen)
    if code is None:
        assert any("wal_checkpoint" in sql for sql in seen)


def test_unexpected_interrupt_is_not_hidden(store, tmp_path, monkeypatch):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    error = sqlite3.OperationalError("interrupted without reaching the deadline")
    error.sqlite_errorcode = sqlite3.SQLITE_INTERRUPT
    monkeypatch.setattr(BlobStore, "maintain", lambda *args, **kwargs: (_ for _ in ()).throw(error))
    with pytest.raises(sqlite3.OperationalError):
        StorageMaintenance("db").tick(threading.Event())


def test_cache_hit_pins_nested_references_until_checkpoint_can_be_saved(store, tmp_path, monkeypatch):
    with store.connection:
        child = store.put("child", {"detail": "retained source"})
        parent = store.put("cached", {"child": child}, cache=True)
        store.connection.execute("UPDATE graph_nodes SET created=0")
    actual_read = store.read

    def evict_before_read(reference, **kwargs):
        with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
            other = BlobStore(connection)
            drain(other, budget=0)
            assert other.exists(parent) and other.exists(child)
        return actual_read(reference, **kwargs)

    monkeypatch.setattr(store, "read", evict_before_read)
    assert store.cached("cached") == (True, {"child": child})
    assert actual_read(child) == {"detail": "retained source"}
    with store.connection:
        store.own("checkpoint", child)
    drain(store)
    oracle(store)


def test_cache_lookup_errors_preserve_transaction_ownership(store):
    with store.connection:
        reference = store.put("cached", {"body": "source"}, cache=True)
    store.connection.executescript(
        "CREATE TRIGGER inject_cache_error BEFORE UPDATE OF created ON graph_nodes "
        "BEGIN SELECT RAISE(ABORT,'injected cache error'); END;"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected cache error"):
        store.cached("cached")
    assert not store.connection.in_transaction
    store.connection.execute("BEGIN")
    with pytest.raises(sqlite3.IntegrityError):
        store.cached("cached")
    assert store.connection.in_transaction
    store.connection.rollback()
    store.connection.execute("DROP TRIGGER inject_cache_error")
    with store.connection:
        store.own("root", reference)
        assert store.cached("cached") == (True, {"body": "source"})
        assert store.connection.in_transaction
    assert store.exists(reference)


def test_text_pack_rejects_oversized_input_before_any_rows_are_written(store, monkeypatch):
    from shyhurricane.graph import blob_store

    monkeypatch.setattr(blob_store, "MAX_DECODED_BYTES", 10)
    with pytest.raises(ValueError, match="decoded size limit"):
        store.put("too-large", {"body": "x" * 2000})
    assert store.connection.execute("SELECT count(*) FROM graph_nodes").fetchone() == (0,)
    assert store.statistics()["stored_payload_bytes"] == 0


def test_writer_contention_defers_and_recovers(store, tmp_path, monkeypatch, caplog):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    with store.connection:
        reference = store.put("retained", {"body": "evidence"})
        store.own("owner", reference)
    store.connection.execute("BEGIN IMMEDIATE")
    caplog.set_level("INFO")
    started = time.monotonic()
    result = StorageMaintenance("db").tick(threading.Event())
    assert time.monotonic() - started < 1
    assert result == {"processed": 0, "pending": True, "deferred": True}
    assert "deferred stage=transaction" in caplog.text
    assert not any(record.levelno >= 30 or record.exc_info for record in caplog.records)
    store.connection.rollback()
    assert not StorageMaintenance("db").tick(threading.Event())["deferred"]
    assert store.read(reference) == {"body": "evidence"}


@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, 517, 262])
def test_contention_preserves_committed_batch(store, tmp_path, monkeypatch, code):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    with store.connection:
        for index in range(400):
            store.put(str(index), {"body": str(index)}, cache=True)
    real_maintain = BlobStore.maintain
    counts = []

    def partial(self, **kwargs):
        counts.append(self.connection.execute("SELECT count(*) FROM graph_cache").fetchone()[0])
        if len(counts) == 2:
            self.connection.execute("DELETE FROM graph_cache")
            error = sqlite3.OperationalError("injected contention")
            error.sqlite_errorcode = code
            raise error
        return real_maintain(self, budget=0, **kwargs)

    monkeypatch.setattr(BlobStore, "maintain", partial)
    result = StorageMaintenance("db").tick(threading.Event())
    assert result == {"processed": 64, "pending": True, "deferred": True}
    assert counts[1] < counts[0]
    assert store.connection.execute("SELECT count(*) FROM graph_cache").fetchone()[0] == counts[1]
    monkeypatch.setattr(BlobStore, "maintain", real_maintain)
    for _ in range(20):
        if not StorageMaintenance("db").tick(threading.Event())["pending"]:
            break
    else:
        pytest.fail("cleanup did not converge after contention")
    assert store.connection.execute("SELECT count(*) FROM graph_cache").fetchone()[0] == 0


@pytest.mark.parametrize("stage", ["validate", "pending", "vacuum", "checkpoint", "checkpoint-result", "unknown"])
def test_contention_at_other_stages(store, tmp_path, monkeypatch, stage):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    monkeypatch.setattr(storage_maintenance, "PASS_ITEMS", 0)
    error = sqlite3.OperationalError("injected contention")
    if stage != "unknown":
        error.sqlite_errorcode = sqlite3.SQLITE_LOCKED

    def fail(*args, **kwargs):
        raise error

    if stage in ("validate", "unknown"):
        monkeypatch.setattr(storage_maintenance, "validate", fail)
    elif stage == "pending":
        monkeypatch.setattr(storage_accounting, "pending", fail)
    else:
        connect = sqlite3.connect

        class Connection:
            def __init__(self, *args, **kwargs):
                self.db = connect(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.db, name)

            def execute(self, sql, *args):
                if stage == "vacuum" and "incremental_vacuum" in sql:
                    raise error
                if stage.startswith("checkpoint") and "wal_checkpoint" in sql:
                    if stage == "checkpoint":
                        raise error
                    return self.db.execute("SELECT 1, 10, 0")
                return self.db.execute(sql, *args)

        monkeypatch.setattr(storage_maintenance.sqlite3, "connect", Connection)
    if stage == "unknown":
        with pytest.raises(sqlite3.OperationalError, match="injected contention"):
            StorageMaintenance("db").tick(threading.Event())
    else:
        result = StorageMaintenance("db").tick(threading.Event())
        assert result["deferred"]
        assert result["processed"] == 0


def test_commit_contention_rolls_back_only_active_batch(store, tmp_path, monkeypatch):
    from shyhurricane.graph import storage_maintenance

    monkeypatch.setattr(storage_maintenance, "persistent_queue_path", lambda *args: tmp_path)
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    with store.connection:
        for index in range(400):
            store.put(str(index), {"body": str(index)}, cache=True)
    connect = sqlite3.connect
    committed = []

    class Connection(sqlite3.Connection):
        def __exit__(self, *args):
            if committed:
                self.rollback()
                error = sqlite3.OperationalError("commit busy")
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error
            result = super().__exit__(*args)
            committed.append(self.execute("SELECT count(*) FROM graph_cache").fetchone()[0])
            return result

    monkeypatch.setattr(
        storage_maintenance.sqlite3, "connect", lambda *args, **kwargs: connect(*args, factory=Connection, **kwargs),
    )
    result = StorageMaintenance("db").tick(threading.Event())
    assert result == {"processed": 64, "pending": True, "deferred": True}
    assert store.connection.execute("SELECT count(*) FROM graph_cache").fetchone()[0] == committed[0]
