"""Small compressed values stay in SQLite; larger values share bounded segment files."""

import os
import re
import sqlite3
import tempfile
from pathlib import Path
from uuid import uuid4

INLINE_BYTES = 64 * 1024
SEGMENT_BYTES = 64 * 1024 * 1024
MAX_BYTES = 260 * 1024 * 1024
NAME = re.compile(r"[0-9a-f]{32}\.pack\Z")


SCHEMA = (
    "CREATE TABLE IF NOT EXISTS graph_file_root(root TEXT NOT NULL);"
    "CREATE TABLE IF NOT EXISTS graph_payload_segments("
    "name TEXT PRIMARY KEY,bytes INTEGER NOT NULL,state TEXT NOT NULL,retired_at REAL,allocated INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS graph_payload_totals(id INTEGER PRIMARY KEY,bytes INTEGER,allocated INTEGER,segments INTEGER);"
    "INSERT OR IGNORE INTO graph_payload_totals VALUES (1,0,0,0);"
    "CREATE TRIGGER IF NOT EXISTS graph_segment_insert AFTER INSERT ON graph_payload_segments BEGIN "
    "UPDATE graph_payload_totals SET bytes=bytes+NEW.bytes,allocated=allocated+NEW.allocated,segments=segments+1 WHERE id=1; END;"
    "CREATE TRIGGER IF NOT EXISTS graph_segment_update AFTER UPDATE OF bytes,allocated ON graph_payload_segments "
    "WHEN NEW.bytes<>OLD.bytes OR NEW.allocated<>OLD.allocated BEGIN "
    "UPDATE graph_payload_totals SET bytes=bytes+NEW.bytes-OLD.bytes,"
    "allocated=allocated+NEW.allocated-OLD.allocated WHERE id=1; END;"
    "CREATE TRIGGER IF NOT EXISTS graph_segment_delete AFTER DELETE ON graph_payload_segments BEGIN "
    "UPDATE graph_payload_totals SET bytes=bytes-OLD.bytes,allocated=allocated-OLD.allocated,segments=segments-1 WHERE id=1; END;"
    "CREATE INDEX IF NOT EXISTS graph_segment_state ON graph_payload_segments(state,name);"
    "CREATE TABLE IF NOT EXISTS graph_shards("
    "ref TEXT PRIMARY KEY,version INTEGER NOT NULL,size INTEGER NOT NULL,stored INTEGER NOT NULL,"
    "payload BLOB,segment TEXT,offset INTEGER,created REAL NOT NULL);"
    "CREATE INDEX IF NOT EXISTS graph_shard_segment ON graph_shards(segment,ref);"
    "CREATE INDEX IF NOT EXISTS graph_shard_created ON graph_shards(created,ref);"
    "CREATE TABLE IF NOT EXISTS graph_inventory_outbox("
    "id TEXT PRIMARY KEY,generation TEXT NOT NULL,sequence INTEGER NOT NULL,"
    "shard TEXT NOT NULL,metadata TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',"
    "UNIQUE(generation,sequence));"
    "CREATE INDEX IF NOT EXISTS graph_inventory_shard ON graph_inventory_outbox(shard);"
    "CREATE TABLE IF NOT EXISTS graph_inventory_totals(id INTEGER PRIMARY KEY,logical INTEGER,stored INTEGER);"
    "INSERT OR IGNORE INTO graph_inventory_totals VALUES (1,0,0);"
    "CREATE TRIGGER IF NOT EXISTS graph_shard_insert AFTER INSERT ON graph_shards BEGIN "
    "UPDATE graph_inventory_totals SET logical=logical+NEW.size,stored=stored+NEW.stored WHERE id=1; END;"
    "CREATE TRIGGER IF NOT EXISTS graph_shard_delete AFTER DELETE ON graph_shards BEGIN "
    "UPDATE graph_inventory_totals SET logical=logical-OLD.size,stored=stored-OLD.stored WHERE id=1; END;"
)


def initialize(connection):
    connection.executescript(SCHEMA)


class PayloadStore:
    def __init__(self, connection):
        self.connection = connection
        filename = connection.execute("PRAGMA database_list").fetchone()[2]
        self.directory = Path(filename).parent / "payload_segments" if filename else None

    def root(self, create=False):
        if self.directory is None:
            row = self.connection.execute("SELECT root FROM graph_file_root LIMIT 1").fetchone()
            if row:
                self.directory = Path(row[0])
            elif create:
                self.directory = Path(tempfile.mkdtemp(prefix="graph-segments-"))
                self.connection.execute("INSERT INTO graph_file_root VALUES (?)", (str(self.directory),))
            else:
                raise FileNotFoundError("Graph payload directory is unavailable")
        if create and not self.directory.exists():
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.sync_directory(self.directory.parent)
        return self.directory

    @staticmethod
    def sync_directory(directory):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def path(self, name):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("Invalid graph payload segment")
        return self.root() / name

    def put(self, payload):
        if len(payload) > MAX_BYTES:
            raise ValueError("Graph payload exceeds stored size limit")
        if len(payload) <= INLINE_BYTES:
            return sqlite3.Binary(payload), None, None
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        self.root(create=True)
        row = self.connection.execute(
            "SELECT name,bytes FROM graph_payload_segments WHERE state='writable' ORDER BY name LIMIT 1"
        ).fetchone()
        if row and row[1] + len(payload) > SEGMENT_BYTES:
            self.connection.execute("UPDATE graph_payload_segments SET state='sealed' WHERE name=?", (row[0],))
            row = None
        if row is None:
            name, offset = uuid4().hex + ".pack", 0
            self.connection.execute(
                "INSERT INTO graph_payload_segments(name,bytes,state) VALUES (?,0,'writable')", (name,)
            )
        else:
            name, offset = row
        path = self.path(name)
        created = not path.exists()
        if offset and (created or path.stat().st_size < offset):
            raise ValueError("Graph payload segment is missing committed bytes")
        with path.open("w+b" if created else "r+b") as stream:
            # A previous process may have died after fsync but before committing metadata.
            stream.truncate(offset)
            stream.seek(offset)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            allocated = os.fstat(stream.fileno()).st_blocks * 512
        if created:
            self.sync_directory(self.directory)
        self.connection.execute(
            "UPDATE graph_payload_segments SET bytes=?,state=?,allocated=? WHERE name=?",
            (offset + len(payload), "sealed" if offset + len(payload) >= SEGMENT_BYTES else "writable", allocated, name),
        )
        return None, name, offset

    def read(self, inline, segment, offset, stored):
        if not isinstance(stored, int) or not 0 <= stored <= MAX_BYTES:
            raise ValueError("Invalid graph payload size")
        if inline is not None:
            if segment is not None or offset is not None or len(inline) != stored:
                raise ValueError("Corrupt inline graph payload")
            return bytes(inline)
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("Invalid graph payload offset")
        return self.read_range(segment, offset, stored)

    def read_range(self, segment, offset, stored, *, stream=None):
        if not isinstance(offset, int) or offset < 0 or not isinstance(stored, int) or not 0 <= stored <= MAX_BYTES:
            raise ValueError("Invalid graph payload range")
        row = self.connection.execute(
            "SELECT bytes FROM graph_payload_segments WHERE name=?", (segment,)
        ).fetchone()
        if row is None or offset + stored > row[0]:
            raise ValueError("Graph payload lies outside its committed segment")
        try:
            if stream is None:
                with self.path(segment).open("rb") as opened:
                    opened.seek(offset)
                    payload = opened.read(stored)
            else:
                stream.seek(offset)
                payload = stream.read(stored)
        except FileNotFoundError as error:
            raise FileNotFoundError("Graph payload segment is unavailable") from error
        if len(payload) != stored:
            raise ValueError("Truncated graph payload segment")
        return payload
