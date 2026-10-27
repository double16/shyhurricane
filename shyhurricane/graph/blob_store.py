"""Compressed, content-addressed graph objects with transactional ownership."""

import hashlib
import json
import os
import time
from contextlib import contextmanager

from shyhurricane.graph import storage_accounting
from shyhurricane.graph.storage_schema import VERSION, initialize, validate

__all__ = ["BlobStore", "VERSION", "initialize", "validate", "cache_budget", "owner_triggers"]

import zstandard

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

    def _pack(self, raw):
        if len(raw) > MAX_DECODED_BYTES:
            raise ValueError("Graph artifact exceeds decoded size limit")
        packed = zstandard.ZstdCompressor(level=1, write_checksum=True).compress(raw)
        codec, payload = ("zstd", packed) if len(packed) < len(raw) else ("raw", raw)
        return hashlib.sha256(raw).hexdigest(), codec, ENCODING_VERSION, len(raw), payload

    def _raw(self, digest, limit=MAX_DECODED_BYTES):
        row = self.connection.execute(
            "SELECT codec,version,size,payload FROM graph_blobs WHERE digest=?", (digest,)
        ).fetchone()
        if row is None:
            raise ValueError("Missing graph artifact content")
        codec, version, size, payload = row
        if version != ENCODING_VERSION or codec not in {"raw", "zstd"}:
            raise ValueError("Unsupported graph artifact encoding")
        if not 0 <= size <= min(limit, MAX_DECODED_BYTES):
            raise ValueError("Graph artifact exceeds decoded size limit")
        try:
            if codec == "zstd" and zstandard.frame_content_size(payload) != size:
                raise ValueError("Corrupt graph artifact size")
            raw = (
                payload
                if codec == "raw"
                else zstandard.ZstdDecompressor().decompress(
                    payload, max_output_size=max(1, size), allow_extra_data=False
                )
            )
        except zstandard.ZstdError as error:
            raise ValueError("Corrupt graph artifact") from error
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Corrupt graph artifact")
        return raw

    def put(self, key, value, *, cache=False):
        """Return an immutable content reference; keys identify optional cache entries only."""
        blobs, children, references = {}, set(), set()
        expanded_bytes = 0

        def encode(item):
            nonlocal expanded_bytes
            if isinstance(item, str):
                if len(item) == 66 and item.startswith("a:") and all(c in "0123456789abcdef" for c in item[2:]):
                    references.add(item)
                if len(item) >= 1024:
                    packed = self._pack(item.encode("utf-8", errors="surrogatepass"))
                    blobs[packed[0]] = packed
                    expanded_bytes += packed[3]
                    children.add(packed[0])
                    return {TEXT_TAG: packed[0]}
            elif isinstance(item, dict):
                encoded = {key: encode(val) for key, val in item.items()}
                return {LITERAL_TAG: encoded} if set(item) in ({TEXT_TAG}, {LITERAL_TAG}) else encoded
            elif isinstance(item, (tuple, list)):
                return [encode(val) for val in item]
            return item

        wire = encode(value)
        raw = json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode("utf-8", errors="surrogatepass")
        if len(raw) + expanded_bytes > MAX_DECODED_BYTES:
            raise ValueError("Graph artifact exceeds decoded size limit")
        packed = self._pack(raw)
        blobs[packed[0]] = packed
        reference = "a:" + packed[0]
        for record in blobs.values():
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_blobs(digest,codec,version,size,payload) VALUES (?,?,?,?,?)", record
            )
        now = time.time()
        # Text leaves precede the artifact. Existing artifact dependencies are immutable.
        for child in children:
            self.connection.execute(
                "INSERT INTO graph_nodes(id,kind,digest,created) VALUES (?,'text',?,?) "
                "ON CONFLICT(id) DO UPDATE SET created=excluded.created,retiring=0",
                ("t:" + child, child, now),
            )
        self.connection.execute(
            "INSERT INTO graph_nodes(id,kind,digest,created) VALUES (?,'artifact',?,?) "
            "ON CONFLICT(id) DO UPDATE SET created=excluded.created,retiring=0",
            (reference, packed[0], now),
        )
        dependencies = {"t:" + child for child in children}
        for child in references:
            if child != reference and self.exists(child):
                dependencies.add(child)
        self.connection.executemany(
            "INSERT OR IGNORE INTO graph_edges(parent,child) VALUES (?,?)",
            ((reference, child) for child in dependencies),
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

    def read(self, ref, *, limit=MAX_DECODED_BYTES):
        with self.snapshot():
            return self._read(ref, limit=limit)

    def _read(self, ref, *, limit=MAX_DECODED_BYTES):
        row = self.connection.execute(
            "SELECT digest FROM graph_nodes WHERE id=? AND kind='artifact' AND retiring=0", (ref,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Graph artifact unavailable: {ref}")
        remaining = limit

        def decode(item):
            nonlocal remaining
            if isinstance(item, dict):
                if set(item) == {TEXT_TAG}:
                    raw = self._raw(item[TEXT_TAG], remaining)
                    remaining -= len(raw)
                    return raw.decode("utf-8", errors="surrogatepass")
                if set(item) == {LITERAL_TAG}:
                    return {key: decode(val) for key, val in item[LITERAL_TAG].items()}
                return {key: decode(val) for key, val in item.items()}
            if isinstance(item, list):
                return [decode(val) for val in item]
            return item

        raw = self._raw(row[0], remaining)
        remaining -= len(raw)
        return decode(json.loads(raw))

    def exists(self, ref):
        return (
            self.connection.execute(
                "SELECT 1 FROM graph_nodes WHERE id=? AND kind='artifact' AND retiring=0", (ref,)
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


def owner_triggers(connection, table, column, key="rowid"):
    """Follow durable SQL owners even when callers update them directly."""
    for action in ("INSERT", "UPDATE"):
        previous = (
            f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||OLD.{key}; "
            if action == "UPDATE"
            else ""
        )
        connection.executescript(
            f"CREATE TRIGGER IF NOT EXISTS blob_{table}_{column}_{action} AFTER {action} ON {table} BEGIN "
            + previous
            + f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||NEW.{key}; "
            f"INSERT INTO graph_object_owners SELECT '{table}:{column}:'||NEW.{key},NEW.{column} "
            f"WHERE NEW.{column} LIKE 'a:%'; END;"
        )
    connection.executescript(
        f"CREATE TRIGGER IF NOT EXISTS blob_{table}_{column}_DELETE AFTER DELETE ON {table} BEGIN "
        f"DELETE FROM graph_object_owners WHERE owner='{table}:{column}:'||OLD.{key}; END;"
    )
