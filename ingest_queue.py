import multiprocessing
import os
from multiprocessing import Queue, Process
from typing import Dict, Tuple

from haystack import Pipeline

from pipeline import build_ingest_pipeline

_ingest_queues: Dict[str, Queue] = {}


def get_ingest_queue(db_path: str) -> Queue:
    abs_path = os.path.abspath(db_path)
    if abs_path not in _ingest_queues:
        _ingest_queues[abs_path] = multiprocessing.Queue()
    return _ingest_queues[abs_path]


def _ingest_worker(db_path: str, queue: Queue):
    pipeline: Pipeline = build_ingest_pipeline(db=db_path)
    while True:
        item = queue.get()
        if item is None:
            break  # Sentinel to stop
        pipeline.run({"input_router": {"text": str(item)}})


def start_ingest_worker(db_path: str) -> Tuple[Queue, Process]:
    queue = get_ingest_queue(db_path)
    process = multiprocessing.Process(target=_ingest_worker, args=(db_path, queue))
    process.start()
    return queue, process
