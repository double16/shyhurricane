import asyncio
import base64
import logging
import os
import re
import sqlite3
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import persistqueue
from persistqueue import Empty
from persistqueue.serializers import pickle as pickle_serializer

from shyhurricane.utils import log_gpu_memory_summary, log_heap_stats

logger = logging.getLogger(__name__)

QUEUE_VACUUM_MIN_FREE_BYTES = 64 * 1024 * 1024
QUEUE_VACUUM_MIN_FREE_RATIO = 0.25
QUEUE_VACUUM_MAX_FREE_BYTES = 1024 * 1024 * 1024
QUEUE_COMPRESSION_MARKER = b"SHQ\x01ZLIB\x00"


class Base64QueueSerializer:
    """Store compressed base64 pickle payloads while accepting older uncompressed records."""

    @staticmethod
    def dumps(value: Any) -> bytes:
        compressed = zlib.compress(pickle_serializer.dumps(value), level=1)
        return base64.b64encode(QUEUE_COMPRESSION_MARKER + compressed)

    @staticmethod
    def loads(data: bytes) -> Any:
        if data.startswith(b"\x80"):
            return pickle_serializer.loads(data)
        payload = base64.b64decode(data, validate=True)
        if payload.startswith(QUEUE_COMPRESSION_MARKER):
            payload = zlib.decompress(payload[len(QUEUE_COMPRESSION_MARKER):])
        return pickle_serializer.loads(payload)


def persistent_queue_path(db: str, queue_name: str) -> Path:
    """Resolve a queue directory without opening or changing its database."""
    if os.path.exists("/data"):
        return Path("/data", "queues", queue_name)
    return Path(Path.home(), ".local", "state", "shyhurricane",
                re.sub(r"[^A-Za-z0-9_.-]", "_", db), queue_name)


def open_persistent_queue(path: str, *, auto_resume: bool = True) -> persistqueue.SQLiteAckQueue:
    """Open a queue and ensure status queries have a covering index."""
    queue = persistqueue.SQLiteAckQueue(
        path=path, auto_commit=True, auto_resume=auto_resume, serializer=Base64QueueSerializer)
    try:
        with queue.tran_lock, queue._putter as connection:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'ack_queue_status_id'"
            ).fetchone()
            if not exists:
                started = time.monotonic()
                logger.info("Creating queue status index in %s", path)
                connection.execute(
                    f"CREATE INDEX IF NOT EXISTS ack_queue_status_id ON {queue._table_name} (status)"
                )
                logger.info("Created queue status index in %s in %.2f seconds", path, time.monotonic() - started)
        return queue
    except BaseException:
        queue.close()
        raise


def get_persistent_queue(db: str, queue_name: str) -> persistqueue.SQLiteAckQueue:
    path = persistent_queue_path(db, queue_name)
    os.makedirs(path, mode=0o755, exist_ok=True)
    return open_persistent_queue(str(path))


def read_active_queue_size(path: Path) -> int:
    """Read an active count without resuming work or sharing SQLite connections."""
    connection = sqlite3.connect((path / "data.db").as_uri() + "?mode=ro", uri=True, timeout=10)
    try:
        return connection.execute(
            "SELECT COUNT(_id) FROM ack_queue_default WHERE status <= 2"
        ).fetchone()[0]
    finally:
        connection.close()


async def persistent_queue_sizes(db: str) -> tuple[int, int]:
    """Read dashboard and status counts off the HTTP event loop."""
    def read():
        return tuple(read_active_queue_size(persistent_queue_path(db, name))
                     for name in ("ingest_queue", "doc_type_queue"))

    return await asyncio.to_thread(read)


class AsyncIngestWriter:
    """Serialize durable writes using a connection owned by a dedicated thread."""

    def __init__(self, path: str):
        self.path = path
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ingest-writer")
        self.queue = None
        self.slot = asyncio.Semaphore(1)
        self.lock = threading.Lock()
        self.closed = False

    def _put(self, item: Any):
        if self.queue is None:
            self.queue = open_persistent_queue(self.path, auto_resume=False)
        return self.queue.put(item)

    async def put(self, item: Any):
        async with self.slot:
            with self.lock:
                if self.closed:
                    raise RuntimeError("Ingest writer is closed")
                future = asyncio.wrap_future(self.executor.submit(self._put, item))
            cancelled = False
            while not future.done():
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    cancelled = True
            result = future.result()
            if cancelled:
                raise asyncio.CancelledError
            return result

    def _close_queue(self):
        if self.queue is not None:
            try:
                self.queue.close()
            finally:
                # persist-queue closes again in __del__; release it on its owning thread.
                self.queue = None

    def close(self, timeout: float = 30):
        """Reject new writes, drain submitted work, and close on the owning thread."""
        with self.lock:
            if self.closed:
                return
            self.closed = True
            future = self.executor.submit(self._close_queue)
        try:
            future.result(timeout=timeout)
        finally:
            self.executor.shutdown(wait=False)


def _vacuum_persistent_queue(queue: persistqueue.SQLiteAckQueue, name: str):
    """Vacuum only when SQLite reports substantial reclaimable database space."""
    with queue.tran_lock:
        cursor = queue._putter.execute(
            "SELECT freelist_count, page_count, page_size "
            "FROM pragma_freelist_count(), pragma_page_count(), pragma_page_size()"
        )
        try:
            free_pages, total_pages, page_size = cursor.fetchone()
        finally:
            cursor.close()
    free_bytes = free_pages * page_size
    free_ratio = free_pages / total_pages if total_pages else 0
    if free_bytes <= QUEUE_VACUUM_MAX_FREE_BYTES and (
            free_bytes < QUEUE_VACUUM_MIN_FREE_BYTES or free_ratio < QUEUE_VACUUM_MIN_FREE_RATIO):
        return
    logger.info("Vacuuming %s: %d reclaimable bytes, %.1f%% free pages", name, free_bytes, free_ratio * 100)
    started = time.monotonic()
    queue.shrink_disk_usage()
    logger.info("Vacuumed %s in %.2f seconds", name, time.monotonic() - started)


def _shrink_persistent_queue(
        queue: persistqueue.SQLiteAckQueue, name: str, keep_latest: int = 200, vacuum: bool = True):
    try:
        acked_count = queue.acked_count()
        if acked_count > keep_latest:
            logger.info("Cleaning %s, retaining %d successful acknowledgements", name, keep_latest)
            # persist-queue emits OFFSET without LIMIT for max_delete=0 with retention.
            # Bound deletion by the entire current backlog instead of a fixed batch size.
            queue.clear_acked_data(max_delete=acked_count if keep_latest else 0, keep_latest=keep_latest)
        if vacuum:
            _vacuum_persistent_queue(queue, name)
    except Exception as e:
        logger.warning("Shrinking queue %s failed: %s", name, e)
    log_heap_stats()
    log_gpu_memory_summary()


def cleanup_persistent_queues_on_startup(db: str):
    """Discard successful acknowledgement history before queue workers start."""
    for queue_name in ("ingest_queue", "doc_type_queue", "scan_finding_queue"):
        queue = get_persistent_queue(db, queue_name)
        try:
            _shrink_persistent_queue(queue, queue_name, keep_latest=0, vacuum=False)
        finally:
            queue.close()


class QueueMaintenance:
    """Schedule queue cleanup by processed count or elapsed maintenance interval."""

    def __init__(self, queue: persistqueue.SQLiteAckQueue, shrink_count: int = 1000,
                 shrink_idle_timeout: float = 600.0):
        self.queue = queue
        self.shrink_count = shrink_count
        self.shrink_idle_timeout = shrink_idle_timeout
        self.count = 0
        self.last_shrink = time.monotonic()

    def check(self):
        if self.count >= self.shrink_count or time.monotonic() - self.last_shrink >= self.shrink_idle_timeout:
            _shrink_persistent_queue(self.queue, os.path.basename(self.queue.path))
            self.last_shrink = time.monotonic()
            self.count = 0


def persistent_queue_get(queue: persistqueue.SQLiteAckQueue, shrink_count: int = 1000,
                         shrink_idle_timeout: float = 600.0, stop_event=None):
    maintenance = QueueMaintenance(queue, shrink_count, shrink_idle_timeout)
    while stop_event is None or not stop_event.is_set():
        maintenance.check()
        try:
            item = queue.get(block=True, timeout=1 if stop_event is not None else 60)
        except Empty:
            maintenance.check()
            if stop_event is None:
                time.sleep(10)
            continue
        if stop_event is not None and stop_event.is_set():
            queue.nack(item)
            return
        if item is None:
            queue.ack(item)
            maintenance.count += 1
            continue
        yield item
        maintenance.count += 1


def get_ingest_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "ingest_queue")


def get_doc_type_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "doc_type_queue")


def get_scan_finding_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "scan_finding_queue")


def active_queue_size(queue) -> int:
    """Return the number of queued and currently processing items."""
    ready_count = getattr(queue, "_count", None)
    unack_count = getattr(queue, "unack_count", None)
    if unack_count is not None and ready_count is not None:
        try:
            return unack_count() + ready_count()
        except (NotImplementedError, OSError):
            pass
    total = getattr(queue, "total", None)
    if total is not None:
        try:
            return total() if callable(total) else total
        except (NotImplementedError, OSError):
            pass
    return queue.active_size()
