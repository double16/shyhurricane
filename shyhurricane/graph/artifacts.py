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
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote

from shyhurricane.graph.artifact_paths import artifact_reference, resolve_artifact_path
from shyhurricane.graph.model import MAX_BYTES, identity
from shyhurricane.graph.svg import is_svg
from shyhurricane.persistent_queue import persistent_queue_path

logger = logging.getLogger(__name__)


class ArtifactStore:
    def __init__(self, db: str):
        self.root = persistent_queue_path(db, "graph_state")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(self.root / "artifacts.sqlite", timeout=30)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS captures (id TEXT PRIMARY KEY, url TEXT, stamp REAL, path TEXT);"
            "CREATE INDEX IF NOT EXISTS capture_url ON captures(url, stamp);"
            "CREATE TABLE IF NOT EXISTS refs (url TEXT, capture_id TEXT, PRIMARY KEY(url,capture_id));"
            "CREATE TABLE IF NOT EXISTS analysis_policies (capture_id TEXT PRIMARY KEY, mode TEXT, "
            "completed_version INTEGER, completed_mode TEXT);"
            "CREATE TABLE IF NOT EXISTS work (id TEXT PRIMARY KEY, status TEXT, error TEXT);"
            "CREATE TABLE IF NOT EXISTS bodies (url TEXT, digest TEXT, path TEXT, PRIMARY KEY(url,digest));"
        )

        if not self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='refs_capture_id'"
        ).fetchone():
            started = time.monotonic()
            logger.info("Creating graph reference index in %s", self.root)
            with self.connection:
                self.connection.execute("CREATE INDEX IF NOT EXISTS refs_capture_id ON refs(capture_id,url)")
            logger.info("Created graph reference index in %.3f seconds", time.monotonic() - started)

    def resolve(self, reference: str | Path) -> Path:
        return resolve_artifact_path(self.root, reference)

    def reference(self, path: str | Path) -> str:
        return artifact_reference(self.root, path)

    def close(self):
        self.connection.close()

    @contextmanager
    def lock(self, key: str):
        with (self.root / f"{identity(key)}.lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def write(self, key: str, value) -> Path:
        path = self.root / f"{identity(key)}.json"
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        with temporary.open("w") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        return path

    def cached(self, key: str, factory):
        with self.lock(key):
            path = self.root / f"{identity(key)}.json"
            if path.exists():
                return json.loads(path.read_text())
            value = factory()
            self.write(key, value)
            return value

    def register(self, event: dict):
        with self.lock(event["id"]):
            existing = self.connection.execute("SELECT path FROM captures WHERE id=?", (event["id"],)).fetchone()
            if existing:
                return json.loads(self.resolve(existing[0]).read_text())
            path = self.write(event["id"], event)
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO captures VALUES (?,?,?,?)",
                    (event["id"], event["data"]["url"], event["observed_at"], self.reference(path)),
                )
                digest = hashlib.sha256((event["data"].get("response_body") or "").encode()).hexdigest()
                self.connection.execute(
                    "INSERT OR IGNORE INTO bodies VALUES (?,?,?)", (event["data"]["url"], digest, self.reference(path))
                )
            return event

    def latest(self, url: str) -> dict | None:
        row = self.connection.execute(
            "SELECT path FROM captures WHERE url=? ORDER BY stamp DESC, id LIMIT 1", (url,)
        ).fetchone()
        return json.loads(self.resolve(row[0]).read_text()) if row else None

    def references(self, capture_id: str, urls: list[str]):
        with self.connection:
            self.connection.executemany("INSERT OR IGNORE INTO refs VALUES (?,?)", ((url, capture_id) for url in urls))

    def dependents(self, url: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT c.path FROM captures c JOIN refs r ON c.id=r.capture_id " "WHERE r.url=?", (url,)
        ).fetchall()
        return [json.loads(self.resolve(row[0]).read_text()) for row in rows]

    def targets(self, capture_id: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT c.path FROM captures c JOIN refs r ON c.url=r.url " "WHERE r.capture_id=?", (capture_id,)
        ).fetchall()
        return [json.loads(self.resolve(row[0]).read_text()) for row in rows]

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
    ):
        from shyhurricane.index.javascript_analysis import _cached_map, _fetch_map, _valid_map, source_map_url

        def valid(content):
            return isinstance(content, str) and len(content.encode()) <= MAX_BYTES and _valid_map(content)

        response_headers = {key.lower(): value for key, value in (response_headers or {}).items()}
        row = self.connection.execute(
            "SELECT path FROM bodies WHERE url=? AND digest=?", (url, original_hash)
        ).fetchone()
        raw = json.loads(self.resolve(row[0]).read_text()) if row else None
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
            explicit = self.latest(explicit_url) if explicit_url else None
            candidate = explicit["data"].get("response_body") if explicit else _cached_map(content_store, explicit_url)
            if valid(candidate):
                return candidate
        map_url = source_map_url(url)
        if not map_url:
            return None
        local = self.latest(map_url)
        candidate = local["data"].get("response_body") if local else _cached_map(content_store, map_url)
        if valid(candidate):
            return candidate
        if not open_world:
            return None
        # Negative results are shared for this exact script and credential context, too.
        key = identity("map-v1", url, original_hash or hashlib.sha256(source.encode()).hexdigest(), headers)
        candidate = self.cached(key, lambda: _fetch_map(map_url, headers))
        return candidate if valid(candidate) else None

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
