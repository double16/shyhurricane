import sqlite3

import pytest

from shyhurricane.graph.storage_schema import initialize
from shyhurricane.graph.storage_tuning import configure


@pytest.mark.parametrize("value", ["0", "-1", "1048577", "invalid"])
def test_invalid_cache(monkeypatch, value):
    monkeypatch.setenv("GRAPH_SQLITE_CACHE_KIB", value)
    with sqlite3.connect(":memory:") as connection, pytest.raises(ValueError):
        configure(connection)


def test_default_and_override(monkeypatch):
    with sqlite3.connect(":memory:") as connection:
        monkeypatch.delenv("GRAPH_SQLITE_CACHE_KIB", raising=False)
        configure(connection)
        assert connection.execute("PRAGMA cache_size").fetchone()[0] == -65536
        monkeypatch.setenv("GRAPH_SQLITE_CACHE_KIB", "1024")
        configure(connection)
        assert connection.execute("PRAGMA cache_size").fetchone()[0] == -1024


def test_ownership_noop_replacement_null_and_key_change():
    from shyhurricane.graph.blob_store import BlobStore, owner_triggers

    connection = sqlite3.connect(":memory:")
    try:
        initialize(connection)
        connection.execute("CREATE TABLE example(id TEXT PRIMARY KEY,ref TEXT)")
        owner_triggers(connection, "example", "ref", "id")
        blobs = BlobStore(connection)
        first = blobs.put("one", {"value": 1})
        second = blobs.put("two", {"value": 2})
        connection.execute("INSERT INTO example VALUES ('first',?)", (first,))
        before = connection.total_changes
        connection.execute("UPDATE example SET ref=ref")
        assert connection.total_changes - before == 1
        connection.execute("UPDATE example SET ref=?", (second,))
        assert connection.execute("SELECT owners FROM graph_nodes WHERE id=?", (first,)).fetchone()[0] == 0
        assert connection.execute("SELECT owners FROM graph_nodes WHERE id=?", (second,)).fetchone()[0] == 1
        connection.execute("UPDATE example SET id='renamed'")
        assert connection.execute("SELECT owner FROM graph_object_owners").fetchone()[0] == "example:ref:renamed"
        connection.execute("UPDATE example SET ref=NULL")
        assert connection.execute("SELECT count(*) FROM graph_object_owners").fetchone()[0] == 0
        assert connection.execute("SELECT owners FROM graph_nodes WHERE id=?", (second,)).fetchone()[0] == 0
    finally:
        connection.close()
