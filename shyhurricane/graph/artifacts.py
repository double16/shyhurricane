"""Persistent captures, shared transformations, and late-arriving reference reconciliation."""

import base64
import fcntl
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager, nullcontext
from urllib.parse import unquote

from shyhurricane.data_paths import persistent_queue_path
from shyhurricane.graph.blob_store import BlobStore, cache_budget, initialize, owner_triggers, validate
from shyhurricane.graph.cache_leases import cache_lease
from shyhurricane.graph.manifest import ManifestStore
from shyhurricane.graph.model import MAX_BYTES, capture_unit_path, identity
from shyhurricane.graph.svg import is_svg

logger = logging.getLogger(__name__)


class ArtifactStore:
    def __init__(self, db: str, *, readonly=False, budget=None):
        self.root = persistent_queue_path(db, "graph_state")
        self.budget = budget
        self.snapshot_reference = None
        if readonly:
            from shyhurricane.graph.sqlite_read import open_read_connection

            self.connection = open_read_connection(self.root / "artifacts.sqlite", budget)
            try:
                validate(self.connection)
            except BaseException:
                self.connection.close()
                raise
            self.blobs = BlobStore(self.connection)
            self.manifest = ManifestStore(self.connection, self.root, initialize=False)
            self.reference_epoch = 0
            return
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        database = self.root / "artifacts.sqlite"
        if not database.exists() and next(self.root.glob("*.json"), None) is not None:
            raise ValueError("Unsupported graph storage version; use a fresh assessment directory")
        self.connection = sqlite3.connect(database, timeout=30)
        try:
            with self.lock("schema"):
                initialize(self.connection)
        except BaseException:
            self.connection.close()
            raise
        os.chmod(database, 0o600)
        self.blobs = BlobStore(self.connection)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS captures (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
            "id TEXT NOT NULL UNIQUE,url TEXT,stamp REAL,path TEXT);"
            "CREATE INDEX IF NOT EXISTS capture_url ON captures(url, stamp);"
            "CREATE TABLE IF NOT EXISTS refs (url TEXT, capture_id TEXT, PRIMARY KEY(url,capture_id));"
            "CREATE TABLE IF NOT EXISTS graph_capture_metadata (capture_id TEXT PRIMARY KEY,method TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS analysis_policies (capture_id TEXT PRIMARY KEY, mode TEXT, "
            "completed_version INTEGER, completed_mode TEXT);"
            "CREATE TABLE IF NOT EXISTS graph_policy_revisions (capture_id TEXT,mode TEXT);"
            "CREATE INDEX IF NOT EXISTS graph_policy_capture ON graph_policy_revisions(capture_id);"
            "CREATE TRIGGER IF NOT EXISTS graph_policy_insert AFTER INSERT ON analysis_policies BEGIN "
            "INSERT INTO graph_policy_revisions VALUES (NEW.capture_id,NEW.mode); END;"
            "CREATE TRIGGER IF NOT EXISTS graph_policy_update AFTER UPDATE OF mode ON analysis_policies "
            "WHEN OLD.mode IS NOT NEW.mode BEGIN "
            "INSERT INTO graph_policy_revisions VALUES (NEW.capture_id,NEW.mode); END;"
            "CREATE TABLE IF NOT EXISTS work (id TEXT PRIMARY KEY, status TEXT, error TEXT);"
            "CREATE TABLE IF NOT EXISTS bodies (url TEXT, digest TEXT, path TEXT, PRIMARY KEY(url,digest));"
            "CREATE TABLE IF NOT EXISTS graph_retained_maps (key TEXT PRIMARY KEY,path TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS graph_reference_revisions (url TEXT,capture_id TEXT,epoch_id INTEGER,"
            "PRIMARY KEY(url,capture_id));"
        )
        self.reference_epoch = 0
        self.manifest = ManifestStore(self.connection, self.root)
        for table in ("captures", "bodies", "graph_retained_maps"):
            owner_triggers(self.connection, table, "path")

        if not self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='refs_capture_id'"
        ).fetchone():
            started = time.monotonic()
            logger.info("Creating graph reference index in %s", self.root)
            with self.connection:
                self.connection.execute("CREATE INDEX IF NOT EXISTS refs_capture_id ON refs(capture_id,url)")
            logger.info("Created graph reference index in %.3f seconds", time.monotonic() - started)

    def read(self, reference, *, limit=None):
        if self.budget is not None:
            self.budget.check()
        value = self.blobs.read(reference, **({"limit": limit} if limit is not None else {}))
        if self.budget is not None:
            self.budget.check()
        return value

    def delete(self, reference):
        with self.connection:
            self.blobs.delete(reference)

    def close(self):
        self.connection.close()

    @contextmanager
    def lock(self, key: str):
        bucket = int(identity(key)[:8], 16) % 64
        with (self.root / f"artifact-lock-{bucket}").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def write(self, key: str, value):
        with nullcontext() if self.connection.in_transaction else self.connection:
            return self.blobs.put(key, value)

    def cached(self, key: str, factory):
        if cache_budget() == 0:
            return factory()
        reference = "a:" + identity("cache", key)
        with cache_lease(self.root, reference):
            found, value = self.blobs.cached(reference)
            if found:
                with self.connection:
                    self.connection.execute("UPDATE graph_cache SET accessed=? WHERE key=?",
                                            (time.time(), reference))
                return value
            value = factory()
            with self.connection:
                self.blobs.put(reference, value, cache=True)
            return value

    def register(self, event: dict):
        with self.lock(event["id"]):
            existing = self.connection.execute("SELECT path FROM captures WHERE id=?", (event["id"],)).fetchone()
            if existing:
                return self.read(existing[0])
            path = self.write(event["id"], event)
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO captures(id,url,stamp,path) VALUES (?,?,?,?)",
                    (event["id"], event["data"]["url"], event["observed_at"], path),
                )
                self.connection.execute("INSERT OR IGNORE INTO graph_capture_metadata VALUES (?,?)",
                                        (event["id"], event["data"]["method"].upper()))
                digest = hashlib.sha256((event["data"].get("response_body") or "").encode(errors="surrogatepass")).hexdigest()
                self.connection.execute(
                    "INSERT OR IGNORE INTO bodies VALUES (?,?,?)", (event["data"]["url"], digest, path)
                )
            unit = self.manifest.unit(event["id"], capture_unit_path(event))
            self.manifest.fact(unit, event["id"], "resource", {
                "id": identity("resource", f"{event['data']['method'].upper()} {event['data']['url']}"),
                "url": event["data"]["url"], "method": event["data"]["method"].upper(),
                "capture_status": "captured",
            })
            return event

    def latest(self, url: str, *, as_of=None) -> dict | None:
        row = self.connection.execute(
            "SELECT path FROM captures WHERE url=? AND (? IS NULL OR stamp<=?) ORDER BY stamp DESC, id LIMIT 1",
            (url, as_of, as_of),
        ).fetchone()
        return self.read(row[0]) if row else None

    def references(self, capture_id: str, urls: list[str]):
        with self.manifest.transaction():
            self.connection.executemany(
                "INSERT OR IGNORE INTO main.refs VALUES (?,?)", ((url, capture_id) for url in urls)
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO main.graph_reference_revisions VALUES (?,?,?)",
                ((url, capture_id, self.reference_epoch) for url in urls),
            )

    def dependents(self, url: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT c.path FROM captures c JOIN refs r ON c.id=r.capture_id " "WHERE r.url=?", (url,)
        ).fetchall()
        return [self.read(row[0]) for row in rows]

    def targets(self, capture_id: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT c.path FROM captures c JOIN refs r ON c.url=r.url " "WHERE r.capture_id=?", (capture_id,)
        ).fetchall()
        return [self.read(row[0]) for row in rows]

    def consuming_documents(self, url: str, budget: int = 1000) -> tuple[list[dict], bool]:
        """Follow supplied script dependencies back to their documents, including lazy chunks."""
        pending = [url]
        seen = set()
        documents = {}
        while pending and len(seen) < budget:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            for event in self.dependents(current):
                data = event["data"]
                headers = {key.lower(): value for key, value in data.get("response_headers", {}).items()}
                mime = headers.get("content-type", "")
                if "html" in mime or is_svg(mime):
                    documents[event["id"]] = event
                elif "javascript" in mime or data["url"].split("?", 1)[0].endswith((".js", ".mjs")):
                    pending.append(data["url"])
        return list(documents.values()), bool(pending)

    def status(self, capture_id: str, status: str, error: str = ""):
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO work VALUES (?,?,?)", (capture_id, status, error[:500]))

    def counts(self) -> dict:
        return dict(self.connection.execute("SELECT status, count(*) FROM work GROUP BY status").fetchall())

    def source_map(
        self,
        url: str,
        source: str,
        headers: dict,
        open_world: bool,
        content_store=None,
        original_hash=None,
        response_headers=None,
        observed_at=None,
    ):
        from shyhurricane.source_maps import _cached_map, _fetch_map, _valid_map, source_map_url

        def valid(content):
            return isinstance(content, str) and len(content.encode()) <= MAX_BYTES and _valid_map(content)

        response_headers = {key.lower(): value for key, value in (response_headers or {}).items()}
        row = self.connection.execute(
            "SELECT path FROM bodies WHERE url=? AND digest=?", (url, original_hash)
        ).fetchone()
        raw = self.read(row[0]) if row else None
        raw_source = (raw or {}).get("data", {}).get("response_body") or ""
        if raw_source and original_hash and hashlib.sha256(raw_source.encode()).hexdigest() == original_hash:
            source = raw_source
        hint = response_headers.get("sourcemap") or response_headers.get("x-sourcemap")
        match = re.search(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)", source)
        hint = hint or (match[1].rstrip("*/") if match else None)
        if hint and hint.startswith("data:"):
            try:
                meta, content = hint.split(",", 1)
                candidate = base64.b64decode(content, validate=True).decode() if ";base64" in meta else unquote(content)
                if valid(candidate):
                    return candidate
            except (ValueError, UnicodeDecodeError):
                pass
        elif hint:
            from shyhurricane.graph.model import web_url

            explicit_url = web_url(hint, url)
            explicit = self.latest(explicit_url, as_of=observed_at) if explicit_url else None
            candidate = explicit["data"].get("response_body") if explicit else _cached_map(content_store, explicit_url)
            if valid(candidate):
                return candidate
        map_url = source_map_url(url)
        if not map_url:
            return None
        local = self.latest(map_url, as_of=observed_at)
        candidate = local["data"].get("response_body") if local else _cached_map(content_store, map_url)
        if valid(candidate):
            return candidate
        key = identity("map-v1", url, original_hash or hashlib.sha256(source.encode()).hexdigest(), headers)
        retained = self.connection.execute("SELECT path FROM graph_retained_maps WHERE key=?", (key,)).fetchone()
        if retained:
            return self.read(retained[0])
        if not open_world:
            return None
        # Negative results are recomputable; successful target responses are retained evidence.
        candidate = self.cached(key, lambda: _fetch_map(map_url, headers))
        if not valid(candidate):
            return None
        reference = self.write(identity("retained-map", key, candidate), candidate)
        with self.connection:
            self.connection.execute("INSERT OR IGNORE INTO graph_retained_maps VALUES (?,?)", (key, reference))
        return candidate

    def deobfuscate(self, source: str, transform):
        return self.cached(identity("deobfuscate-v1", source), lambda: transform(source))


def recovered_sources(source_map: str) -> list[tuple[str, str]]:
    """Read embedded source text without trusting map paths as filesystem paths."""
    result = []
    remaining = MAX_BYTES

    def visit(data):
        nonlocal remaining
        for section in data.get("sections", []):
            if isinstance(section, dict) and isinstance(section.get("map"), dict):
                visit(section["map"])
        for name, content in zip(data.get("sources", []), data.get("sourcesContent", []) or []):
            if isinstance(name, str) and isinstance(content, str):
                size = len(content.encode())
                if size <= remaining:
                    result.append((name, content))
                    remaining -= size

    visit(json.loads(source_map))
    return result
