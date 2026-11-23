"""Immutable inventory payloads, durably published before database references."""

import hashlib
import json
import logging
import re
import sqlite3
import struct
import time
from collections import OrderedDict
from contextlib import nullcontext
from pathlib import Path

import zstandard

from shyhurricane.graph.payload_store import PayloadStore, initialize
from shyhurricane.graph.performance import count as metric_count
from shyhurricane.graph.performance import label, measured, phase, timed

logger = logging.getLogger(__name__)

MAX_RECORDS = 500
SHARD_BYTES = 4 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
MAGIC = b"SHYSHRD2"
HEADER = struct.Struct("<8sIQ")
ENTRY = struct.Struct("<III32s")
REFERENCE = re.compile(r"s:[0-9a-f]{64}\Z")


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def batches(records):
    """Bound decoded arrays, retaining individually oversized records."""
    batch, size = [], 2
    for record in records:
        length = len(encode(record))
        if length + 2 > MAX_BYTES:
            raise ValueError("Graph inventory record exceeds decoded size limit")
        addition = length + bool(batch)
        if batch and (len(batch) == MAX_RECORDS or size + addition > SHARD_BYTES):
            yield batch
            batch, size, addition = [], 2, length
        batch.append(record)
        size += addition
    if batch:
        yield batch


class ShardStore:
    def __init__(self, root, connection=None):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.owns_connection = connection is None
        self.connection = connection or sqlite3.connect(self.root / "shards.sqlite")
        if self.owns_connection:
            initialize(self.connection)
        self.payloads = PayloadStore(self.connection)
        self.files = OrderedDict()

    def close(self):
        for stream in self.files.values():
            stream.close()
        self.files.clear()
        if self.owns_connection:
            self.connection.close()

    @measured("shard_write", logger)
    def put(self, records):
        if not records or len(records) > MAX_RECORDS or any(not isinstance(record, dict) for record in records):
            raise ValueError("Graph shard requires between 1 and 500 records")
        metric_count("records", len(records))
        label(caller_transaction=self.connection.in_transaction)
        with phase("serialize"):
            raw = [encode(record) for record in records]
        size = sum(map(len, raw)) + len(raw) + 1
        if size > MAX_BYTES or (size > SHARD_BYTES and len(records) != 1):
            raise ValueError("Graph shard exceeds decoded size limit")
        metric_count("logical_bytes", size)
        with phase("compress"):
            compressor = zstandard.ZstdCompressor(level=1, write_checksum=True)
            frames = [compressor.compress(value) for value in raw]
        offset = HEADER.size + len(records) * ENTRY.size
        entries = []
        for value, frame in zip(raw, frames, strict=True):
            entries.append(ENTRY.pack(offset, len(frame), len(value), hashlib.sha256(value).digest()))
            offset += len(frame)
        header = HEADER.pack(MAGIC, len(records), size) + b"".join(entries)
        reference = "s:" + hashlib.sha256(header).hexdigest()
        label(shard_id=reference)
        metric_count("stored_bytes", len(header) + sum(map(len, frames)))
        with phase("persist"), nullcontext() if self.connection.in_transaction else self.connection:
            if not self.connection.in_transaction:
                self.connection.execute("BEGIN IMMEDIATE")
            existing = self.connection.execute("SELECT 1 FROM graph_shards WHERE ref=?", (reference,)).fetchone()
            if existing:
                metric_count("shards_reused")
                self.connection.execute("UPDATE graph_shards SET created=? WHERE ref=?", (time.time(), reference))
            else:
                metric_count("shards_written")
                container = header + b"".join(frames)
                inline, segment, start = self.payloads.put(container)
                self.connection.execute(
                    "INSERT INTO graph_shards VALUES (?,2,?,?,?,?,?,?)",
                    (reference, size, len(container), inline, segment, start, time.time()),
                )
        return reference

    @timed("payload_io")
    def _slice(self, row, start, length):
        identity, _, stored, inline, segment, offset = row
        if start < 0 or length < 0 or start + length > stored:
            raise ValueError("Invalid graph shard encoding range")
        if inline:
            data = self.connection.execute(
                "SELECT substr(payload,?,?) FROM graph_shards WHERE rowid=?", (start + 1, length, identity),
            ).fetchone()[0]
        else:
            if not isinstance(offset, int) or offset < 0:
                raise ValueError("Invalid graph shard encoding offset")
            if segment not in self.files:
                metric_count("segment_opens")
                try:
                    self.files[segment] = self.payloads.path(segment).open("rb")
                except FileNotFoundError as error:
                    raise FileNotFoundError("Graph payload segment is unavailable") from error
                if len(self.files) > 2:
                    self.files.popitem(last=False)[1].close()
            else:
                metric_count("segment_hits")
            self.files.move_to_end(segment)
            data = self.payloads.read_range(segment, offset + start, length, stream=self.files[segment])
        if len(data) != length:
            raise ValueError("Truncated graph shard encoding")
        metric_count("read_bytes", len(data))
        return data

    def _header(self, reference):
        if not isinstance(reference, str) or not REFERENCE.fullmatch(reference):
            raise ValueError("Invalid graph shard reference")
        with phase("payload_metadata"):
            selected = self.connection.execute(
                "SELECT rowid,size,stored,payload IS NOT NULL,segment,offset,version FROM graph_shards WHERE ref=?",
                (reference,),
            ).fetchone()
        if selected is None:
            raise FileNotFoundError("Graph shard is unavailable")
        row, version = selected[:-1], selected[-1]
        if version != 2 or not 0 <= row[1] <= MAX_BYTES:
            raise ValueError("Graph shard exceeds decoded size or encoding limit")
        prefix = self._slice(row, 0, HEADER.size)
        magic, count, size = HEADER.unpack(prefix)
        if magic != MAGIC or not 1 <= count <= MAX_RECORDS or size != row[1]:
            raise ValueError("Invalid graph shard encoding header")
        header = prefix + self._slice(row, HEADER.size, count * ENTRY.size)
        with phase("payload_verify"):
            if hashlib.sha256(header).hexdigest() != reference[2:]:
                raise ValueError("Corrupt graph shard digest")
        return row, header, count

    def _record(self, row, header, count, position, limit):
        if not isinstance(position, int) or not 0 <= position < count:
            raise ValueError("Inventory shard position is invalid")
        offset, stored, size, digest = ENTRY.unpack_from(header, HEADER.size + position * ENTRY.size)
        if offset < len(header) or not 0 < size <= min(limit, MAX_BYTES):
            raise ValueError("Graph shard exceeds decoded size limit")
        frame = self._slice(row, offset, stored)
        try:
            if zstandard.frame_content_size(frame) != size:
                raise ValueError("Corrupt graph shard frame size")
            with phase("payload_decompress"):
                raw = zstandard.ZstdDecompressor().decompress(frame, max_output_size=size, allow_extra_data=False)
        except zstandard.ZstdError as error:
            raise ValueError("Corrupt graph shard encoding") from error
        metric_count("decoded_bytes", len(raw))
        with phase("payload_verify"):
            if hashlib.sha256(raw).digest() != digest:
                raise ValueError("Corrupt graph shard record digest")
        with phase("payload_json"):
            record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError("Invalid graph shard records")
        metric_count("records")
        return record

    def read_record(self, reference, position, *, limit=MAX_BYTES):
        row, header, count = self._header(reference)
        return self._record(row, header, count, position, limit)

    def read(self, reference, *, limit=MAX_BYTES):
        row, header, count = self._header(reference)
        if row[1] > min(limit, MAX_BYTES):
            raise ValueError("Graph shard exceeds decoded size limit")
        return [self._record(row, header, count, position, limit) for position in range(count)]
