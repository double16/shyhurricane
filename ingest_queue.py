import logging
import multiprocessing
import os
import re
from multiprocessing import Queue, Process
from pathlib import Path
from typing import Dict, Tuple

import persistqueue
from haystack import Pipeline

from pipeline import build_ingest_pipeline
from utils import GeneratorConfig

_ingest_queues: Dict[str, persistqueue.SQLiteQueue] = {}

logger = logging.getLogger(__name__)


def get_ingest_queue(db: str) -> persistqueue.SQLiteQueue:
    if db not in _ingest_queues:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), "ingest_queue")
        os.makedirs(path.parent, mode=0o755, exist_ok=True)
        _ingest_queues[db] = persistqueue.SQLiteQueue(path=str(path), auto_commit=True)
    return _ingest_queues[db]


def _ingest_worker(db: str, generator_config: GeneratorConfig, queue_path: str):
    queue = persistqueue.SQLiteQueue(path=queue_path, auto_commit=True)
    pipeline: Pipeline = build_ingest_pipeline(db=db, generator_config=generator_config)
    while True:
        item = queue.get()
        if item is None:
            logger.info("Exiting the ingest queue")
            break  # Sentinel to stop
        try:
            pipeline.run({"input_router": {"text": str(item)}})
        except Exception as e:
            logger.error("Error in ingestion pipeline", exc_info=e)


def start_ingest_worker(db: str, generator_config: GeneratorConfig) -> Tuple[persistqueue.SQLiteQueue, Process]:
    queue = get_ingest_queue(db)
    process = multiprocessing.Process(target=_ingest_worker, args=(db, generator_config, queue.path))
    process.start()
    return queue, process
