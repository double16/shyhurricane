"""Packed files retain pinned content and reclaim dead space in bounded passes."""

import os
import sqlite3
import time
from contextlib import closing

import pytest

from shyhurricane.graph import payload_store, segment_maintenance
from shyhurricane.graph.blob_store import initialize
from shyhurricane.graph.payload_store import PayloadStore
from shyhurricane.graph.segment_maintenance import GRACE_SECONDS, SegmentMaintenance


def add_shard(connection, payload, reference, *, pinned=False):
    store = PayloadStore(connection)
    inline, segment, offset = store.put(payload)
    connection.execute(
        "INSERT INTO graph_shards VALUES (?,1,?,?,?,?,?,?)",
        (reference, len(payload), len(payload), inline, segment, offset, time.time() - GRACE_SECONDS - 10),
    )
    if pinned:
        connection.execute(
            "INSERT INTO graph_inventory_outbox(id,generation,sequence,shard,metadata) VALUES (?, ?,0,?,'[]')",
            (reference, reference, reference),
        )
    return segment


def test_pinned_shards_survive_and_unpinned_shards_retire(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        with connection:
            name = add_shard(connection, b"retained", "keep", pinned=True)
            add_shard(connection, b"discarded", "remove")
        maintenance = SegmentMaintenance(tmp_path)
        assert maintenance.tick(connection) == 1
        assert connection.execute("SELECT ref FROM graph_shards").fetchall() == [("keep",)]
        assert PayloadStore(connection).path(name).exists()
        with connection:
            connection.execute("DELETE FROM graph_inventory_outbox")
        maintenance.after = ""
        assert maintenance.tick(connection) == 2
        assert connection.execute("SELECT state FROM graph_payload_segments").fetchone() == ("retired",)
        # Retired files remain available to SQLite snapshots until the grace interval ends.
        assert PayloadStore(connection).path(name).exists()
        with connection:
            connection.execute("UPDATE graph_payload_segments SET retired_at=?", (time.time() - GRACE_SECONDS - 1,))
        maintenance.tick(connection)
        assert not PayloadStore(connection).path(name).exists()
        assert connection.execute("SELECT * FROM graph_payload_segments").fetchall() == []
        assert connection.execute("SELECT bytes,allocated,segments FROM graph_payload_totals").fetchone() == (0, 0, 0)
        maintenance.close()


def test_compaction_preserves_snapshot_reads_and_bounds_items(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 100)
    path = tmp_path / "artifacts.sqlite"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        initialize(connection)
        with connection:
            name = add_shard(connection, b"a" * 10, "a", pinned=True)
            add_shard(connection, b"b" * 10, "b", pinned=True)
            add_shard(connection, b"c" * 80, "dead")
        reader = sqlite3.connect(path)
        try:
            reader.execute("BEGIN")
            original = reader.execute("SELECT payload,segment,offset,stored FROM graph_shards WHERE ref='a'").fetchone()
            maintenance = SegmentMaintenance(tmp_path)
            assert maintenance.tick(connection, limit=1) == 2  # Delete one dead shard, move one live shard.
            assert connection.execute("SELECT count(*) FROM graph_shards WHERE segment=?", (name,)).fetchone() == (1,)
            assert PayloadStore(reader).read(*original) == b"a" * 10
            maintenance.tick(connection, limit=1)
            maintenance.tick(connection, limit=1)
            for reference, expected in (("a", b"a" * 10), ("b", b"b" * 10)):
                row = connection.execute(
                    "SELECT payload,segment,offset,stored FROM graph_shards WHERE ref=?", (reference,)
                ).fetchone()
                assert PayloadStore(connection).read(*row) == expected
            assert connection.execute("SELECT state FROM graph_payload_segments WHERE name=?", (name,)).fetchone() == (
                "retired",
            )
            assert PayloadStore(reader).read(*original) == b"a" * 10
            maintenance.close()
        finally:
            reader.close()


def test_orphan_tail_and_directory_scan_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        with connection:
            name = add_shard(connection, b"keep", "keep", pinned=True)
        store = PayloadStore(connection)
        with store.path(name).open("ab") as stream:
            stream.write(b"uncommitted")
        orphan = store.root() / ("0" * 32 + ".pack")
        orphan.write_bytes(b"orphan")
        (store.root() / "unrelated.txt").write_text("keep")
        (store.root() / ("1" * 32 + ".pack")).mkdir()
        maintenance = SegmentMaintenance(tmp_path)
        assert maintenance.tick(connection, deadline=time.monotonic() - 1) == 0
        for _ in range(10):
            maintenance.tick(connection, limit=1)
            if not maintenance.pending:
                break
        assert not orphan.exists()
        assert store.path(name).read_bytes() == b"keep"
        assert (store.root() / "unrelated.txt").exists()
        maintenance.close()
        maintenance.close()
        with pytest.raises(ValueError):
            maintenance.tick(connection, limit=0)


def test_compaction_failure_rolls_back_references(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 100)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        with connection:
            name = add_shard(connection, b"a" * 10, "a", pinned=True)
            add_shard(connection, b"b" * 90, "dead")
            connection.execute("DELETE FROM graph_shards WHERE ref='dead'")
        maintenance = SegmentMaintenance(tmp_path)
        original_put = PayloadStore.put

        def fail_after_append(self, value):
            original_put(self, value)
            raise OSError("disk unavailable")

        monkeypatch.setattr(PayloadStore, "put", fail_after_append)
        with pytest.raises(OSError, match="disk unavailable"):
            maintenance.tick(connection)
        row = connection.execute("SELECT payload,segment,offset,stored FROM graph_shards WHERE ref='a'").fetchone()
        assert row[1] == name
        assert PayloadStore(connection).read(*row) == b"a" * 10
        monkeypatch.setattr(PayloadStore, "put", original_put)
        maintenance.after = ""
        maintenance.tick(connection)
        maintenance.close()


def test_compaction_byte_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 100)
    monkeypatch.setattr(segment_maintenance, "COPY_BYTES", 10)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        with connection:
            name = add_shard(connection, os.urandom(10), "a", pinned=True)
            add_shard(connection, os.urandom(10), "b", pinned=True)
            add_shard(connection, os.urandom(80), "dead")
        maintenance = SegmentMaintenance(tmp_path)
        maintenance.tick(connection)
        assert connection.execute("SELECT count(*) FROM graph_shards WHERE segment=?", (name,)).fetchone() == (1,)
        assert maintenance.pending
        maintenance.close()
