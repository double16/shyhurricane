"""Bounded SQLite writer caches for graph artifacts and checkpoints."""

import os

CACHE_DEFAULT_KIB = 65536


def configure(connection):
    try:
        value = int(os.environ.get("GRAPH_SQLITE_CACHE_KIB", CACHE_DEFAULT_KIB))
    except ValueError as error:
        raise ValueError("GRAPH_SQLITE_CACHE_KIB must be an integer between 1 and 1048576") from error
    if not 1 <= value <= 1048576:
        raise ValueError("GRAPH_SQLITE_CACHE_KIB must be between 1 and 1048576")
    connection.execute(f"PRAGMA cache_size=-{value}")

