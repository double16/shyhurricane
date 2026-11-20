"""Packed payloads bound filesystem entries and recover uncommitted append tails."""

import os
import sqlite3
import subprocess
import sys
from contextlib import closing

import pytest

from shyhurricane.graph import payload_store
from shyhurricane.graph.blob_store import BlobStore, initialize
from shyhurricane.graph.payload_store import PayloadStore


def test_small_values_create_no_payload_files_and_large_values_share_segments(tmp_path):
    with closing(sqlite3.connect(tmp_path / "data.sqlite")) as connection:
        initialize(connection)
        store = PayloadStore(connection)
        for _ in range(1000):
            payload = os.urandom(128)
            with connection:
                location = store.put(payload)
            assert store.read(*location, len(payload)) == payload
        assert not (tmp_path / "payload_segments").exists()
        values = [os.urandom(128 * 1024) for _ in range(40)]
        locations = []
        for payload in values:
            with connection:
                locations.append(store.put(payload))
        assert len(list(store.root().glob("*.pack"))) == 1
        assert all(store.read(*location, len(payload)) == payload
                   for location, payload in zip(locations, values, strict=True))


def test_append_rollback_and_reopen(tmp_path):
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    initialize(connection)
    store = PayloadStore(connection)
    first = os.urandom(128 * 1024)
    with connection:
        location = store.put(first)
    connection.execute("BEGIN IMMEDIATE")
    store.put(os.urandom(128 * 1024))
    connection.rollback()
    connection.close()
    with closing(sqlite3.connect(path)) as connection:
        store = PayloadStore(connection)
        assert store.read(*location, len(first)) == first
        second = os.urandom(128 * 1024)
        with connection:
            second_location = store.put(second)
        assert second_location[2] == len(first)
        assert store.read(*second_location, len(second)) == second
        assert store.path(location[1]).stat().st_size == len(first) + len(second)


def test_rollover_and_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 16)
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 100)
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as connection:
        initialize(connection)
        store = PayloadStore(connection)
        with connection:
            first = store.put(b"a" * 80)
            second = store.put(b"b" * 80)
        assert first[1] != second[1]
        for name in ("../other", "unsafe.pack", None):
            with pytest.raises(ValueError):
                store.path(name)
        for args in ((b"x", None, None, 2), (None, first[1], -1, 1),
                     (None, first[1], 81, 1), (None, "0" * 32 + ".pack", 0, 1)):
            with pytest.raises(ValueError):
                store.read(*args)
        monkeypatch.setattr(payload_store, "MAX_BYTES", 4)
        with pytest.raises(ValueError):
            store.put(b"large")
        with pytest.raises(ValueError):
            store.read(None, first[1], 0, 5)


def test_artifact_deduplication_does_not_append_duplicate_bytes(tmp_path):
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as connection:
        initialize(connection)
        blobs = BlobStore(connection)
        value = {"body": os.urandom(200000).hex()}
        with connection:
            first = blobs.put("first", value)
        before = connection.execute("SELECT sum(bytes) FROM graph_payload_segments").fetchone()[0]
        with connection:
            assert blobs.put("second", value) == first
        assert connection.execute("SELECT sum(bytes) FROM graph_payload_segments").fetchone()[0] == before
        assert blobs.read(first) == value
        stats = blobs.statistics()
        assert stats["segment_count"] == 1
        assert stats["segment_bytes"] == before
        assert stats["segment_allocated_bytes"] == sum(path.stat().st_blocks * 512 for path in blobs.payloads.root().glob("*.pack"))


def test_process_exit_before_commit_preserves_previous_payload(tmp_path):
    path = tmp_path / "state.sqlite"
    with closing(sqlite3.connect(path)) as connection:
        initialize(connection)
        with connection:
            location = PayloadStore(connection).put(b"a" * 100000)
    result = subprocess.run(
        [sys.executable, "-c", """
import os
import sqlite3
import sys
from shyhurricane.graph.payload_store import PayloadStore
c = sqlite3.connect(sys.argv[1])
c.execute("BEGIN IMMEDIATE")
PayloadStore(c).put(b"uncommitted" * 10000)
os._exit(17)
""", str(path)], check=False, timeout=30,
    )
    assert result.returncode == 17
    with closing(sqlite3.connect(path)) as connection:
        store = PayloadStore(connection)
        assert store.read(*location, 100000) == b"a" * 100000
        with connection:
            new = store.put(b"b" * 100000)
        assert new[1] == location[1]
        assert new[2] == 100000
        assert store.path(new[1]).stat().st_size == 200000


@pytest.mark.parametrize("missing", [True, False])
def test_missing_committed_bytes_are_never_replaced(tmp_path, missing):
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as connection:
        initialize(connection)
        store = PayloadStore(connection)
        with connection:
            location = store.put(b"a" * 100000)
        path = store.path(location[1])
        if missing:
            path.unlink()
        else:
            path.write_bytes(b"truncated")
        with pytest.raises(ValueError, match="missing committed bytes"), connection:
            store.put(b"b" * 100000)
        with pytest.raises((ValueError, FileNotFoundError)):
            store.read(*location, 100000)


def test_memory_database_and_read_validation(monkeypatch):
    with closing(sqlite3.connect(":memory:")) as connection:
        initialize(connection)
        store = PayloadStore(connection)
        with pytest.raises(FileNotFoundError):
            store.root()
        monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
        with connection:
            location = store.put(b"value")
        reopened = PayloadStore(connection)
        assert reopened.read(*location, 5) == b"value"
        assert reopened.root() == store.root()
        assert reopened.read(b"", None, None, 0) == b""
        for args in ((b"x", "bad", None, 1), (b"x", None, 0, 1),
                     (b"", None, None, -1), (b"", None, None, "0")):
            with pytest.raises(ValueError):
                reopened.read(*args)
        store.path(location[1]).unlink()
        store.root().rmdir()
