"""Transaction-scoped identifier reuse."""
import sqlite3

import pytest

from shyhurricane.graph.manifest import ManifestStore


def store():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE graph_terms(key INTEGER PRIMARY KEY,value TEXT UNIQUE)")
    manifest = ManifestStore(connection, ".", initialize=False)
    return connection, manifest


def test_batch_reuses_terms_and_clears_cache():
    connection, manifest = store()
    statements = []
    connection.set_trace_callback(statements.append)
    with manifest.batch():
        first = manifest._term("shared")
        assert manifest._term("shared") == first
    assert sum("INSERT OR IGNORE INTO graph_terms" in sql for sql in statements) == 1
    assert manifest.term_cache == {}
    connection.close()


def test_rollback_does_not_reuse_invalid_identifier():
    connection, manifest = store()
    with pytest.raises(ValueError), manifest.batch():
        manifest._term("rolled-back")
        raise ValueError("abort")
    assert connection.execute("SELECT count(*) FROM graph_terms").fetchone()[0] == 0
    with manifest.batch():
        manifest._term("committed")
        manifest._term("rolled-back")
    assert connection.execute("SELECT count(*) FROM graph_terms").fetchone()[0] == 2
    connection.close()


def test_atomic_writer_contention(tmp_path):
    path = tmp_path / "wal.sqlite"
    first = sqlite3.connect(path, timeout=0.01)
    first.execute("PRAGMA journal_mode=WAL")
    first.execute("CREATE TABLE graph_terms(key INTEGER PRIMARY KEY,value TEXT UNIQUE)")
    first.commit()
    second = sqlite3.connect(path, timeout=0.01)
    manifest = ManifestStore(second, ".", initialize=False)
    first.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.OperationalError) as failure:
        with manifest.batch(atomic=True):
            pytest.fail("writer lock must precede callback")
    from shyhurricane.graph.retry_policy import transient_neo4j_error
    assert transient_neo4j_error(failure.value)
    assert not second.in_transaction
    first.rollback()
    with manifest.batch(atomic=True):
        manifest._term("resumed")
    assert second.execute("SELECT count(*) FROM graph_terms").fetchone()[0] == 1
    assert not transient_neo4j_error(sqlite3.OperationalError("invalid"))
    first.close()
    second.close()
