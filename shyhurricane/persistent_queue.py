import base64
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import persistqueue
from persistqueue import Empty
from persistqueue.serializers import pickle as pickle_serializer

from shyhurricane.utils import log_gpu_memory_summary, log_heap_stats

logger = logging.getLogger(__name__)


class Base64QueueSerializer:
    """Store base64-encoded pickle payloads while accepting existing binary pickle records."""

    @staticmethod
    def dumps(value: Any) -> bytes:
        return base64.b64encode(pickle_serializer.dumps(value))

    @staticmethod
    def loads(data: bytes) -> Any:
        if data.startswith(b"\x80"):
            return pickle_serializer.loads(data)
        return pickle_serializer.loads(base64.b64decode(data, validate=True))


def get_persistent_queue(db: str, queue_name: str) -> persistqueue.SQLiteAckQueue:
    if os.path.exists("/data"):
        # Running inside a container
        path = Path("/data", "queues", queue_name)
    else:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), queue_name)
    os.makedirs(path, mode=0o755, exist_ok=True)
    return persistqueue.SQLiteAckQueue(path=str(path), auto_commit=True, serializer=Base64QueueSerializer)


def _shrink_persistent_queue(queue: persistqueue.SQLiteAckQueue, name: str, keep_latest: int = 200):
    try:
        acked_count = queue.acked_count()
        if acked_count <= keep_latest:
            return
        logger.info("Shrinking %s, retaining %d successful acknowledgements", name, keep_latest)
        # persist-queue emits OFFSET without LIMIT for max_delete=0 with retention.
        # Bound deletion by the entire current backlog instead of a fixed batch size.
        queue.clear_acked_data(max_delete=acked_count if keep_latest else 0, keep_latest=keep_latest)
        queue.shrink_disk_usage()
    except Exception as e:
        logger.warning("Shrinking queue %s failed: %s", name, e)
    log_heap_stats()
    log_gpu_memory_summary()


def cleanup_persistent_queues_on_startup(db: str):
    """Discard successful acknowledgement history before queue workers start."""
    for queue_name in ("ingest_queue", "doc_type_queue", "scan_finding_queue"):
        queue = get_persistent_queue(db, queue_name)
        try:
            _shrink_persistent_queue(queue, queue_name, keep_latest=0)
        finally:
            queue.close()


class QueueMaintenance:
    """Schedule queue cleanup by processed count or elapsed maintenance interval."""

    def __init__(self, queue: persistqueue.SQLiteAckQueue, shrink_count: int = 1000,
                 shrink_idle_timeout: float = 60.0):
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
                         shrink_idle_timeout: float = 60.0):
    maintenance = QueueMaintenance(queue, shrink_count, shrink_idle_timeout)
    while True:
        maintenance.check()
        try:
            item = queue.get(block=True, timeout=60)
        except Empty:
            maintenance.check()
            time.sleep(10)
            continue
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
