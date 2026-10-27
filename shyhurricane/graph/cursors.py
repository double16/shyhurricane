"""Opaque, expiring analysis continuations; independent from immutable saved result pages."""

import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from shyhurricane.graph.budget import QueryBudget

TTL_SECONDS = 600
MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_ACTIVE = 16
MAX_RETAINED = 64
MAX_STORE_BYTES = 256 * 1024 * 1024


class QueryCursors:
    def __init__(self, root, budget=None):
        self.budget = budget or QueryBudget()
        self.root = Path(root) / "graph_queries"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.root / "cursors.sqlite", timeout=0.05)
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS cursors (id TEXT PRIMARY KEY,expires REAL NOT NULL,state TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS cursor_expiry ON cursors(expires);"
            "CREATE TABLE IF NOT EXISTS responses (id TEXT PRIMARY KEY,result TEXT NOT NULL);"
        )

        self.connection.set_progress_handler(lambda: int(self.budget.remaining() <= 0), 1000)
        with self.budget.lock:
            self.budget.interrupts.add(self.connection.interrupt)

    def close(self):
        with self.budget.lock:
            self.budget.interrupts.discard(self.connection.interrupt)
            self.connection.close()

    @contextmanager
    def transaction(self):
        self.budget.check()
        self.connection.execute("SAVEPOINT checkpoint")
        try:
            yield
            with self.budget.checkpoint():
                self.budget.check()
                self.connection.execute("RELEASE checkpoint")
        except BaseException:
            self.connection.execute("ROLLBACK TO checkpoint")
            self.connection.execute("RELEASE checkpoint")
            raise

    @contextmanager
    def locked(self, token):
        bucket = int(hashlib.sha256(str(token).encode()).hexdigest()[:2], 16) % MAX_ACTIVE
        with (self.root / f"lock-{bucket}").open("a") as stream:
            os.chmod(stream.name, 0o600)
            while True:
                self.budget.check()
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.budget.cancelled.wait(min(0.05, self.budget.remaining()))
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def encode(self, state):
        chunks, size = [], 0
        for chunk in json.JSONEncoder(sort_keys=True).iterencode(state):
            self.budget.check()
            size += len(chunk.encode())
            if size > MAX_STATE_BYTES:
                raise ValueError("Graph continuation state budget reached; narrow the query")
            chunks.append(chunk)
        return "".join(chunks)

    def save(self, state, *, expires=None):
        data = self.encode(state)
        with self.transaction():
            self.connection.execute("DELETE FROM cursors WHERE expires<=?", (time.time(),))
            self.connection.execute("DELETE FROM responses WHERE id NOT IN (SELECT id FROM cursors)")
            if (
                self.connection.execute(
                    "SELECT count(*) FROM cursors c WHERE NOT EXISTS (SELECT 1 FROM responses r WHERE r.id=c.id)"
                ).fetchone()[0]
                >= MAX_ACTIVE
            ):
                raise ValueError("Too many active graph continuations; finish or expire an existing query")
            count, used = self.connection.execute(
                "SELECT count(*),coalesce(sum(length(state)),0) FROM cursors"
            ).fetchone()
            used += self.connection.execute("SELECT coalesce(sum(length(result)),0) FROM responses").fetchone()[0]
            if count >= MAX_RETAINED or used + len(data.encode()) > MAX_STORE_BYTES:
                raise ValueError("Graph continuation storage budget reached; narrow the query or wait for expiry")
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode()).hexdigest()
            expires = expires if expires is not None else time.time() + TTL_SECONDS
            self.connection.execute("INSERT INTO cursors VALUES (?,?,?)", (digest, expires, data))
        os.chmod(self.root / "cursors.sqlite", 0o600)
        return token

    def load(self, token):
        if not isinstance(token, str) or len(token) != 43:
            raise ValueError("Invalid graph continuation")
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = self.connection.execute("SELECT expires,state FROM cursors WHERE id=?", (digest,)).fetchone()
        if row is None or row[0] <= time.time():
            raise ValueError("Graph continuation expired or unavailable; restart the query")
        return json.loads(row[1]), row[0]

    def response(self, token):
        self.load(token)  # Response replay has the same fixed expiry as the original read.
        row = self.connection.execute(
            "SELECT result FROM responses WHERE id=?", (hashlib.sha256(token.encode()).hexdigest(),)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def complete(self, token, result):
        data = self.encode(result)
        with self.transaction():
            used = self.connection.execute("SELECT coalesce(sum(length(state)),0) FROM cursors").fetchone()[0]
            used += self.connection.execute("SELECT coalesce(sum(length(result)),0) FROM responses").fetchone()[0]
            if used + len(data.encode()) > MAX_STORE_BYTES:
                raise ValueError("Graph continuation storage budget reached; narrow the query")
            self.connection.execute(
                "INSERT OR REPLACE INTO responses VALUES (?,?)", (hashlib.sha256(token.encode()).hexdigest(), data)
            )

    def remove(self, token):
        with self.transaction():
            self.connection.execute("DELETE FROM cursors WHERE id=?", (hashlib.sha256(token.encode()).hexdigest(),))
