"""Compressed, content-addressed graph objects with transactional ownership."""

import hashlib
import json
import logging
import os
import time
from contextlib import contextmanager

from shyhurricane.graph import storage_accounting
from shyhurricane.graph.payload_store import PayloadStore
from shyhurricane.graph.performance import count, label, measured, phase, timed
from shyhurricane.graph.storage_schema import VERSION, initialize, validate

__all__ = ["BlobStore", "VERSION", "initialize", "validate", "cache_budget", "owner_triggers"]

import zstandard

logger = logging.getLogger(__name__)

ENCODING_VERSION = 1
DEFAULT_CACHE_BYTES = 256 * 1024 * 1024
MAX_DECODED_BYTES = 256 * 1024 * 1024
TEXT_TAG = "$graph_text"
LITERAL_TAG = "$graph_literal"


def cache_budget():
    value = int(os.environ.get("GRAPH_ARTIFACT_CACHE_MAX_BYTES", DEFAULT_CACHE_BYTES))
    if value < 0:
        raise ValueError("GRAPH_ARTIFACT_CACHE_MAX_BYTES must be non-negative")
    return value


class BlobStore:
    def __init__(self, connection):
        self.connection = connection
        self.payloads = PayloadStore(connection)

    @timed("compress")
    def _pack(self, raw):
        count("logical_bytes", len(raw))
        if len(raw) > MAX_DECODED_BYTES:
            raise ValueError("Graph artifact exceeds decoded size limit")
        packed = zstandard.ZstdCompressor(level=1, write_checksum=True).compress(raw)
        codec, payload = ("zstd", packed) if len(packed) < len(raw) else ("raw", raw)
        count("stored_bytes", len(payload))
        return hashlib.sha256(raw).hexdigest(), codec, ENCODING_VERSION, len(raw), payload

    def _raw(self, digest, limit=MAX_DECODED_BYTES):
        with phase("payload_metadata"):
            row = self.connection.execute(
                "SELECT codec,version,size,stored,payload,segment,offset FROM graph_blobs WHERE digest=?", (digest,)
            ).fetchone()
        if row is None:
            raise ValueError("Missing graph artifact content")
        codec, version, size, stored, inline, segment, offset = row
        with phase("payload_io"):
            payload = self.payloads.read(inline, segment, offset, stored)
        count("read_bytes", len(payload))
        if version != ENCODING_VERSION or codec not in {"raw", "zstd"}:
            raise ValueError("Unsupported graph artifact encoding")
        if not 0 <= size <= min(limit, MAX_DECODED_BYTES):
            raise ValueError("Graph artifact exceeds decoded size limit")
        try:
            if codec == "zstd" and zstandard.frame_content_size(payload) != size:
                raise ValueError("Corrupt graph artifact size")
            with phase("payload_decompress"):
                raw = (
                    payload
                    if codec == "raw"
                    else zstandard.ZstdDecompressor().decompress(
                        payload, max_output_size=max(1, size), allow_extra_data=False
                    )
                )
        except zstandard.ZstdError as error:
            raise ValueError("Corrupt graph artifact") from error
        count("decoded_bytes", len(raw))
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Corrupt graph artifact")
        return raw

    @measured("artifact_write", logger, summary_interval=60)
    def put(self, key, value, *, cache=False, capture=False):
        """Return an immutable content reference; keys identify optional cache entries only."""
        if capture:
            event = {**value, "data": dict(value["data"])}
            bodies = {}
            for field in ("request_body", "response_body"):
                body = event["data"].get(field)
                if isinstance(body, str):
                    bodies[field] = self.put("capture-body", body)
                    event["data"][field] = None
            value = {"event": event, "bodies": bodies}
        references = set()

        def visit(item):
            if isinstance(item, str) and len(item) == 66 and item.startswith("a:"):
                references.add(item)
            elif isinstance(item, dict):
                for value in item.values():
                    visit(value)
            elif isinstance(item, (tuple, list)):
                for value in item:
                    visit(value)

        visit(value)
        with phase("serialize"):
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8", errors="surrogatepass")
        digest, codec, version, size, payload = self._pack(raw)
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        existing = self.connection.execute("SELECT 1 FROM graph_blobs WHERE digest=?", (digest,)).fetchone()
        inline, segment, offset = (None, None, None) if existing else self.payloads.put(payload)
        self.connection.execute(
            "INSERT OR IGNORE INTO graph_blobs(digest,codec,version,size,stored,payload,segment,offset) "
            "VALUES (?,?,?,?,?,?,?,?)", (digest, codec, version, size, len(payload), inline, segment, offset),
        )
        reference = "a:" + digest
        label(artifact_id=reference)
        now = time.time()
        self.connection.execute(
            "INSERT INTO graph_nodes(id,kind,digest,created) VALUES (?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET created=excluded.created,retiring=0",
            (reference, "capture" if capture else "artifact", digest, now),
        )
        self.connection.executemany(
            "INSERT OR IGNORE INTO graph_edges(parent,child) VALUES (?,?)",
            ((reference, child) for child in references if child != reference and self.exists(child)),
        )
        if cache:
            self.connection.execute(
                "INSERT INTO graph_cache VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET "
                "ref=excluded.ref,accessed=excluded.accessed",
                (key, reference, now),
            )
        return reference

    @contextmanager
    def snapshot(self):
        own = not self.connection.in_transaction
        if own:
            self.connection.execute("BEGIN")
        try:
            yield
        finally:
            if own:
                self.connection.rollback()

    def cached(self, key):
        # Renew the staging root before releasing the cache lookup transaction. This
        # protects nested references until a caller can persist its next checkpoint.
        own = not self.connection.in_transaction
        if own:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT ref FROM graph_cache WHERE key=?", (key,)).fetchone()
            if row:
                self.connection.execute("UPDATE graph_nodes SET created=? WHERE id=?", (time.time(), row[0]))
            if own:
                self.connection.commit()
        except BaseException:
            if own:
                self.connection.rollback()
            raise
        return (True, self.read(row[0])) if row else (False, None)

    @measured("artifact_read", logger, summary_interval=60)
    def read(self, ref, *, limit=MAX_DECODED_BYTES):
        with self.snapshot():
            return self._read(ref, limit=limit)

    def _read(self, ref, *, limit=MAX_DECODED_BYTES):
        row = self.connection.execute(
            "SELECT digest,kind FROM graph_nodes WHERE id=? AND kind IN ('artifact','capture') AND retiring=0", (ref,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Graph artifact unavailable: {ref}")
        raw = self._raw(row[0], limit)
        label(artifact_id="a:" + row[0])
        with phase("payload_json"):
            value = json.loads(raw)
        if row[1] == "capture":
            event = value["event"]
            remaining = limit - len(raw)
            for field, reference in value["bodies"].items():
                body = self.read(reference, limit=remaining)
                remaining -= len(body.encode("utf-8", errors="surrogatepass"))
                if remaining < 0:
                    raise ValueError("Graph artifact exceeds decoded size limit")
                event["data"][field] = body
            return event
        return value

    def exists(self, ref):
        return (
            self.connection.execute(
                "SELECT 1 FROM graph_nodes WHERE id=? AND kind IN ('artifact','capture') AND retiring=0", (ref,)
            ).fetchone()
            is not None
        )

    def own(self, owner, ref):
        if ref is None:
            self.connection.execute("DELETE FROM graph_object_owners WHERE owner=?", (owner,))
        else:
            self.connection.execute(
                "INSERT INTO graph_object_owners VALUES (?,?) ON CONFLICT(owner) DO UPDATE SET ref=excluded.ref",
                (owner, ref),
            )

    def delete(self, ref):
        storage_accounting.retire(self.connection, ref)

    def _cache_bytes(self):
        return self.connection.execute("SELECT cached FROM graph_storage_totals WHERE id=1").fetchone()[0]

    def maintain(self, *, budget=None, batch=500):
        return storage_accounting.maintain(self.connection, cache_budget() if budget is None else budget, batch)

    def statistics(self):
        return storage_accounting.statistics(self.connection, cache_budget())



def owner_sql(table, column, key, action):
    """Generate ownership maintenance without churning unchanged roots."""
    guard = (
        f"WHEN OLD.{key} IS NOT NEW.{key} OR OLD.{column} IS NOT NEW.{column} "
        if action == "UPDATE" else ""
    )
    previous = (
        f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||OLD.{key} "
        f"AND OLD.{key} IS NOT NEW.{key}; "
        if action == "UPDATE" else ""
    )
    return (
        f"CREATE TRIGGER IF NOT EXISTS blob_{table}_{column}_{action} AFTER {action} ON {table} "
        + guard + "BEGIN " + previous
        + f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||NEW.{key} "
        f"AND (NEW.{column} IS NULL OR NEW.{column} NOT LIKE 'a:%'); "
        f"INSERT INTO graph_object_owners SELECT '{table}:{column}:'||NEW.{key},NEW.{column} "
        f"WHERE NEW.{column} LIKE 'a:%' ON CONFLICT(owner) DO UPDATE SET ref=excluded.ref "
        "WHERE ref IS NOT excluded.ref; END;"
    )


def owner_triggers(connection, table, column, key="rowid"):
    """Follow durable SQL owners even when callers update them directly."""
    for action in ("INSERT", "UPDATE"):
        connection.executescript(owner_sql(table, column, key, action))
    connection.executescript(
        f"CREATE TRIGGER IF NOT EXISTS blob_{table}_{column}_DELETE AFTER DELETE ON {table} BEGIN "
        f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||OLD.{key}; END;"
    )
