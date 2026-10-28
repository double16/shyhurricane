"""Work generations survive retries, restarts, and concurrent enrichment."""

import sqlite3
from contextlib import closing

import pytest

from shyhurricane.investigation import jobs
from shyhurricane.investigation.storage import CorrelationStore, store_path
from tests.investigation.test_storage import publish


def test_generations_protect_new_work_from_old_completion_and_failure():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {})
        old = store.work(1)
        with store.connection:
            store.enqueue("correlate", "a")
        new = store.work(1)
        assert new["generation"] > old["generation"]
        store.failed(old, ValueError(), transient=False)
        assert store.work(1) == new
        with store.connection:
            store.acknowledge(old)
        assert store.work(1) == new
        store.failed(new, TimeoutError(), transient=True)
        assert store.work(1) is None
        with store.connection:
            store.connection.execute("UPDATE jobs SET due=0")
        new = store.work(1)
        store.failed(new, ValueError(), transient=False)
        assert store.work(2) is None
        assert store.retry() == 1
        assert store.work(2)["generation"] > new["generation"]


def test_refresh_sweep_finishes_prefix_and_coalesces_new_revisions(monkeypatch):
    monkeypatch.setattr(jobs, "BATCH_SIZE", 2)
    with closing(CorrelationStore("test")) as store:
        for key in ("a", "b", "c"):
            publish(store, key)
        # work() has scanned only the first two IDs; finish that initial pass.
        store.sweep(1)
        store.sweep(1)
        store.sweep(2)
        assert store.setting("sweep")["after"] == "b"
        store.sweep(3)
        assert store.setting("swept") == [2, 2]
        store.sweep(3)
        assert store.setting("sweep")["after"] == "b"
        store.sweep(3)
        assert store.setting("swept") == [3, 2]
        assert store.work(3)
        with store.connection:
            store.enqueue("correlate", "c", revision=0, force=False)
        assert store.work_status()["correlate"]["pending"] == 3


def test_idle_and_selection_use_partial_index_without_findings_scan():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {})
        statements = []
        store.connection.set_trace_callback(statements.append)
        assert store.next_job(1)["kind"] == "correlate"
        statements.clear()
        assert store.next_job(1)
        assert not any("FROM findings WHERE id>" in sql for sql in statements)
        plan = store.connection.execute(
            "EXPLAIN QUERY PLAN SELECT kind,key FROM jobs INDEXED BY ready_jobs "
            "WHERE state='pending' AND due<=? ORDER BY due,kind,key LIMIT 1",
            (1,),
        ).fetchall()
        assert any("ready_jobs" in row[3] for row in plan)
        assert not any("TEMP B-TREE" in row[3] for row in plan)


def test_old_schema_is_rejected_without_changing_it():
    path = store_path("test")
    path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE old_data (value TEXT)")
    with pytest.raises(ValueError, match="rebuild"):
        CorrelationStore("test")
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("old_data",)]


def test_identical_reconciliation_does_not_schedule_new_generation():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {"severity": "high"}, source_revision=2)
        task = store.work(0)
        store.submit("a", "example.com", {"severity": "high"}, source_revision=2)
        store.submit("a", "example.com", {"severity": "low"}, source_revision=1)
        assert store.work(0) == task


def test_new_graph_revision_preserves_transient_backoff():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {})
        task = store.work(1)
        store.failed(task, TimeoutError(), transient=True)
        before = store.connection.execute("SELECT due,attempts FROM jobs WHERE kind='correlate'").fetchone()
        assert store.work(2) is None
        after = store.connection.execute("SELECT due,attempts FROM jobs WHERE kind='correlate'").fetchone()
        assert after == before


def test_policy_refresh_with_same_graph_revision_is_enqueued(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        publish(store)
        monkeypatch.setattr(jobs, "POLICY_VERSION", 3)
        assert store.work(1)
