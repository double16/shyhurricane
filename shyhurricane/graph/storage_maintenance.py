"""Short committed storage batches; deadline exhaustion is a normal yield."""

import logging
import sqlite3
import time
from contextlib import closing

from shyhurricane.data_paths import persistent_queue_path
from shyhurricane.graph import storage_accounting
from shyhurricane.graph.blob_store import BlobStore, cache_budget, validate

logger = logging.getLogger(__name__)
PASS_SECONDS = 2
PASS_ITEMS = 500
COMMIT_ITEMS = 64


class StorageMaintenance:
    def __init__(self, db):
        self.root = persistent_queue_path(db, "graph_state")

    def tick(self, stop_event):
        path = self.root / "artifacts.sqlite"
        if not path.exists():
            return {"processed": 0, "pending": False, "deferred": False}
        started, processed = time.monotonic(), 0
        deadline = started + PASS_SECONDS
        deferred, code, stage = False, None, "connect"
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0.05)) as connection:
                try:
                    stage = "validate"
                    validate(connection)
                    connection.set_progress_handler(lambda: int(stop_event.is_set() or time.monotonic() >= deadline), 1000)
                    while processed < PASS_ITEMS and not stop_event.is_set() and time.monotonic() < deadline:
                        try:
                            with connection:
                                stage = "transaction"
                                connection.execute("BEGIN IMMEDIATE")
                                stage = "batch"
                                result = BlobStore(connection).maintain(batch=min(COMMIT_ITEMS, PASS_ITEMS - processed))
                                stage = "commit"
                            processed += result["processed"]
                            if not result["pending"]:
                                break
                        except sqlite3.OperationalError as error:
                            if getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_INTERRUPT or (
                                not stop_event.is_set() and time.monotonic() < deadline
                            ):
                                raise
                            break
                    connection.set_progress_handler(None, 0)
                    stage = "pending"
                    waiting = storage_accounting.pending(connection, cache_budget())
                    # Space reclamation gets its own short slice even if accounting yielded.
                    if not stop_event.is_set():
                        reclaim_deadline = time.monotonic() + 0.2
                        connection.set_progress_handler(lambda: int(time.monotonic() >= reclaim_deadline), 1000)
                        try:
                            stage = "vacuum"
                            connection.execute("PRAGMA incremental_vacuum(128)").fetchall()
                            stage = "checkpoint"
                            checkpoint = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                            deferred = bool(checkpoint[0])
                            if deferred:
                                code = sqlite3.SQLITE_BUSY
                        except sqlite3.OperationalError as error:
                            if getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_INTERRUPT:
                                raise
                finally:
                    connection.set_progress_handler(None, 0)
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            if code is None or code & 0xFF not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            deferred = True
            waiting = True
        if deferred:
            logger.info(
                "Graph storage maintenance deferred stage=%s sqlite_code=%s processed=%s "
                "seconds=%.3f next_attempt_seconds=1",
                stage, code, processed, time.monotonic() - started,
            )
        else:
            logger.info(
                "Graph storage maintenance processed=%s pending=%s seconds=%.3f",
                processed,
                waiting,
                time.monotonic() - started,
            )
        return {"processed": processed, "pending": waiting, "deferred": deferred}

    def statistics(self):
        path = self.root / "artifacts.sqlite"
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as connection:
            validate(connection)
            connection.execute("PRAGMA query_only=ON")
            with BlobStore(connection).snapshot():
                result = BlobStore(connection).statistics()
            wal = path.with_name(path.name + "-wal")
            result["wal_bytes"] = wal.stat().st_size if wal.exists() else 0
            result["allocated_bytes"] = sum(file.stat().st_blocks * 512 for file in (path, wal) if file.exists())
            return result
