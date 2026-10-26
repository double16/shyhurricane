"""Exact-key cache leases without holding filesystem locks across nested parsers."""

import os
import sqlite3
import time
from contextlib import closing, contextmanager
from uuid import uuid4

import psutil


@contextmanager
def cache_lease(root, reference):
    """Coordinate factories in a small database independent of artifact write transactions."""
    path = root / "cache-leases.sqlite"
    token = uuid4().hex
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        os.chmod(path, 0o600)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS leases (ref TEXT PRIMARY KEY,pid INTEGER,token TEXT,expires REAL)"
        )
        while True:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT pid,expires FROM leases WHERE ref=?", (reference,)).fetchone()
                if row is None or row[1] <= time.time() or not psutil.pid_exists(row[0]):
                    connection.execute(
                        "INSERT OR REPLACE INTO leases VALUES (?,?,?,?)",
                        (reference, os.getpid(), token, time.time() + 3600),
                    )
                    acquired = True
                else:
                    acquired = False
            if acquired:
                break
            time.sleep(0.05)
        try:
            yield
        finally:
            with connection:
                connection.execute("DELETE FROM leases WHERE ref=? AND token=?", (reference, token))
