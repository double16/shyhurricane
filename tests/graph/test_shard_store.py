"""Durable shards preserve bounded payloads and reject corrupt references."""

import hashlib
from unittest.mock import Mock

import pytest
import zstandard

from shyhurricane.graph import payload_store, shard_store
from shyhurricane.graph.shard_store import ShardStore, batches


@pytest.fixture
def store(tmp_path):
    shards = ShardStore(tmp_path)
    try:
        yield shards
    finally:
        shards.close()


def test_round_trip_determinism_and_bounds(store):
    records = [{"id": str(i), "value": "é"} for i in range(1001)]
    groups = list(batches(records))
    assert list(map(len, groups)) == [500, 500, 1]
    ref = store.put(groups[0])
    assert store.put(groups[0]) == ref
    assert store.read(ref) == groups[0]
    assert list(store.root.glob(".staging-*")) == []
    for bad in ([], records):
        with pytest.raises(ValueError):
            store.put(bad)
    for bad in ("../other", "s:../../etc/passwd", None):
        with pytest.raises(ValueError):
            store.read(bad)
    with pytest.raises(ValueError, match="decoded size"):
        store.read(ref, limit=1)


def test_byte_bounds(monkeypatch, store):
    monkeypatch.setattr(shard_store, "SHARD_BYTES", 32)
    monkeypatch.setattr(shard_store, "MAX_BYTES", 128)
    records = [{"value": "x" * 40}, {"value": "y" * 40}]
    assert list(batches(records)) == [[records[0]], [records[1]]]
    ref = store.put([records[0]])
    assert store.read(ref) == [records[0]]
    with pytest.raises(ValueError):
        store.put(records)
    with pytest.raises(ValueError):
        list(batches([{"value": "x" * 200}]))


def test_corrupt_missing_and_invalid_payload(tmp_path):
    store = ShardStore(tmp_path)
    ref = store.put([{"id": "one"}])
    original = store.connection.execute("SELECT payload FROM graph_shards WHERE ref=?", (ref,)).fetchone()[0]

    def replace(payload, reference=ref, version=2):
        with store.connection:
            store.connection.execute("UPDATE graph_shards SET payload=?,stored=?,version=? WHERE ref=?",
                                     (payload, len(payload), version, reference))

    replace(b"corrupt")
    with pytest.raises(ValueError, match="encoding"):
        store.read(ref)
    changed = bytearray(original)
    changed[shard_store.HEADER.size + 12] ^= 1
    replace(bytes(changed))
    with pytest.raises(ValueError, match="digest"):
        store.read(ref)
    changed = bytearray(original)
    changed[-1] ^= 1
    replace(bytes(changed))
    with pytest.raises(ValueError, match="encoding"):
        store.read(ref)
    replace(original, version=1)
    with pytest.raises(ValueError, match="encoding limit"):
        store.read(ref)
    replace(original)
    for position in (-1, 1, "0"):
        with pytest.raises(ValueError, match="position"):
            store.read_record(ref, position)
    with pytest.raises(ValueError, match="decoded size"):
        store.read_record(ref, 0, limit=1)
    with pytest.raises(FileNotFoundError):
        store.read("s:" + "0" * 64)
    store.close()


def test_selected_record_reads_only_header_and_one_frame(tmp_path, monkeypatch):
    import os

    store = ShardStore(tmp_path)
    records = [{"id": str(index), "data": os.urandom(2000).hex()} for index in range(500)]
    reference = store.put(records)
    stored = store.connection.execute("SELECT stored FROM graph_shards").fetchone()[0]
    reads = []
    original = store._slice

    def selected(row, start, length):
        reads.append(length)
        return original(row, start, length)

    monkeypatch.setattr(store, "_slice", selected)
    assert store.read_record(reference, 419) == records[419]
    assert sum(reads) < stored / 10
    assert len(list(store.payloads.root().glob("*.pack"))) == 1
    assert store.read(reference) == records
    store.close()


def test_authenticated_frame_and_header_bounds(tmp_path):
    store = ShardStore(tmp_path)
    compressor = zstandard.ZstdCompressor(write_checksum=True)

    def injected(raw, *, offset=None, declared=None, count=1, magic=shard_store.MAGIC,
                 frame_raw=None, digest=None):
        frame = compressor.compress(raw if frame_raw is None else frame_raw)
        start = shard_store.HEADER.size + shard_store.ENTRY.size
        size = len(raw) + 2
        header = shard_store.HEADER.pack(magic, count, size) + shard_store.ENTRY.pack(
            start if offset is None else offset, len(frame), len(raw) if declared is None else declared,
            hashlib.sha256(raw).digest() if digest is None else digest,
        )
        reference = "s:" + hashlib.sha256(header).hexdigest()
        payload = header + frame
        with store.connection:
            store.connection.execute("INSERT OR REPLACE INTO graph_shards VALUES (?,2,?,?,?,NULL,NULL,0)",
                                     (reference, size, len(payload), payload))
        return reference

    with pytest.raises(ValueError, match="records"):
        store.read(injected(b"[]"))
    with pytest.raises(ValueError, match="frame size"):
        store.read(injected(b"{}", declared=4))
    with pytest.raises(ValueError, match="record digest"):
        store.read(injected(b"{}", digest=b"x" * 32))
    with pytest.raises(ValueError, match="decoded size"):
        store.read(injected(b"{}", offset=0))
    with pytest.raises(ValueError, match="header"):
        store.read(injected(b"{}", count=0))
    with pytest.raises(ValueError, match="header"):
        store.read(injected(b"{}", magic=b"BADSHARD"))
    with pytest.raises(ValueError, match="encoding range"):
        store.read(injected(b"{}", offset=100000))
    with pytest.raises(ValueError, match="500 records"):
        store.put([1])
    store.close()


def test_failed_sync_cleans_temporary(store, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    monkeypatch.setattr(payload_store.os, "fsync", Mock(side_effect=OSError("disk failure")))
    with pytest.raises(OSError):
        store.put([{"id": "one"}])
    assert store.connection.execute("SELECT count(*) FROM graph_shards").fetchone()[0] == 0


def test_segment_read_handles_are_bounded_and_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 1)
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    store = ShardStore(tmp_path)
    references = [store.put([{"id": str(index)}]) for index in range(3)]
    handles = []
    for index, reference in enumerate(references):
        assert store.read_record(reference, 0) == {"id": str(index)}
        handles.append(next(reversed(store.files.values())))
    assert len(store.files) == 2 and handles[0].closed
    assert store.read_record(references[0], 0) == {"id": "0"}
    store.close()
    assert all(handle.closed for handle in handles)


def test_segment_disappearance_and_invalid_offsets_are_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    store = ShardStore(tmp_path)
    reference = store.put([{"id": "one"}])
    name = store.connection.execute("SELECT segment FROM graph_shards").fetchone()[0]
    store.payloads.path(name).unlink()
    with pytest.raises(FileNotFoundError, match="unavailable"):
        store.read_record(reference, 0)
    with store.connection:
        store.connection.execute("UPDATE graph_shards SET offset=NULL")
    with pytest.raises(ValueError, match="offset"):
        store.read_record(reference, 0)
    store.close()
