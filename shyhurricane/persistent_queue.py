import logging
import os
import re
import time
from pathlib import Path

import persistqueue
from persistqueue import Empty

logger = logging.getLogger(__name__)


def get_persistent_queue(db: str, queue_name: str) -> persistqueue.SQLiteAckQueue:
    if os.path.exists("/data"):
        # Running inside a container
        path = Path("/data", "queues", queue_name)
    else:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), queue_name)
    os.makedirs(path.parent, mode=0o755, exist_ok=True)
    return persistqueue.SQLiteAckQueue(path=str(path), auto_commit=True)


def _shrink_persistent_queue(queue: persistqueue.SQLiteAckQueue, name: str):
    logger.info(f"Shrinking {name}")
    try:
        queue.clear_acked_data(max_delete=1000, keep_latest=0)
        queue.shrink_disk_usage()
    except Exception as e:
        logger.debug("Shrinking queue %s failed: %s", name, e)


def persistent_queue_get(queue: persistqueue.SQLiteAckQueue, shrink_count: int = 1000,
                         shrink_idle_timeout: float = 60.0):
    name = os.path.basename(queue.path)
    count = 0
    last_shrink = time.time()
    while True:
        if count % shrink_count == (shrink_count - 1):
            _shrink_persistent_queue(queue, name)
            last_shrink = time.time()

        try:
            item = queue.get(block=True, timeout=60)
        except Empty:
            if count > 0 and (time.time() - last_shrink) > shrink_idle_timeout:
                _shrink_persistent_queue(queue, name)
                last_shrink = time.time()
                count = 0
            time.sleep(10)
            continue
        count += 1
        if item is None:
            queue.ack(item)
            continue
        yield item


def get_ingest_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "ingest_queue")


def get_doc_type_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "doc_type_queue")
