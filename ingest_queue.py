import json
import logging
import multiprocessing
import os
import re
import sys
from pathlib import Path
from typing import Tuple

import persistqueue
from haystack import Pipeline

from pipeline import build_ingest_pipeline
from shyhurricane.task_queue import TaskPool
from utils import GeneratorConfig

logger = logging.getLogger(__name__)


def get_ingest_queue(db: str) -> persistqueue.SQLiteQueue:
    if os.path.exists("/data"):
        # Running inside a container
        path = Path("/data", "queues", "ingest_queue")
    else:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), "ingest_queue")
    os.makedirs(path.parent, mode=0o755, exist_ok=True)
    return persistqueue.SQLiteQueue(path=str(path), auto_commit=True)


def _ingest_worker(db: str, generator_config: GeneratorConfig):
    queue = get_ingest_queue(db)
    pipeline: Pipeline = build_ingest_pipeline(db=db, generator_config=generator_config)
    while True:
        item = queue.get()
        try:
            pipeline.run({"input_router": {"text": str(item)}})
        except Exception as e:
            url = None
            try:
                url = json.loads(item).get("request", {}).get("endpoint", None)
            except Exception as e:
                pass
            logger.error(f"Error in ingestion pipeline for {url} {len(item)} bytes, {e}:\n{item[0:1024]} ...",
                         exc_info=e)
            sys.exit(1)


def start_ingest_worker(db: str, generator_config: GeneratorConfig, pool_size: int = 1) -> Tuple[
    persistqueue.SQLiteQueue, TaskPool]:
    assert pool_size > 0
    queue = get_ingest_queue(db)
    processes = []
    for idx in range(pool_size):
        process = multiprocessing.Process(target=_ingest_worker, args=(db, generator_config))
        process.start()
        processes.append(process)
    return queue, TaskPool(processes)
