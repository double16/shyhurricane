"""Scoped SQLite wall-clock accounting without retaining statements or values."""

import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar

_active = ContextVar("graph_batch_timing", default=None)


@contextmanager
def account():
    stats = {"sql_seconds": 0.0, "sql_calls": 0, "sql_families": {}}
    token = _active.set(stats)
    try:
        yield stats
    finally:
        _active.reset(token)


def timed(call, *args, **kwargs):
    stats = _active.get()
    if stats is None:
        return call(*args, **kwargs)
    started = time.monotonic()
    try:
        return call(*args, **kwargs)
    finally:
        elapsed = time.monotonic() - started
        stats["sql_seconds"] += elapsed
        family = "other"
        if args and isinstance(args[0], str) and args[0].lstrip().upper().startswith("INSERT"):
            for table in ("graph_blobs", "graph_nodes", "graph_facts"):
                if table + "(" in args[0]:
                    family = table
                    break
        bucket = stats["sql_families"].setdefault(family, {"calls": 0, "seconds": 0.0})
        bucket["calls"] += 1
        bucket["seconds"] += elapsed
        stats["sql_calls"] += 1


class Cursor(sqlite3.Cursor):
    def execute(self, *args, **kwargs):
        return timed(super().execute, *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return timed(super().executemany, *args, **kwargs)

    def fetchone(self):
        return timed(super().fetchone)

    def fetchall(self):
        return timed(super().fetchall)

    def __next__(self):
        return timed(super().__next__)


class Connection(sqlite3.Connection):
    def cursor(self, factory=Cursor):
        return super().cursor(factory)

    def execute(self, *args, **kwargs):
        if _active.get() is None:
            return super().execute(*args, **kwargs)
        return self.cursor().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        if _active.get() is None:
            return super().executemany(*args, **kwargs)
        return self.cursor().executemany(*args, **kwargs)
