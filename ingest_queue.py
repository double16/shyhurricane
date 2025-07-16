import logging
import multiprocessing
from multiprocessing import Queue, Process
from typing import Dict, Tuple

from haystack import Pipeline

from pipeline import build_ingest_pipeline
from utils import GeneratorConfig

_ingest_queues: Dict[str, Queue] = {}

logger = logging.getLogger(__name__)


def get_ingest_queue(db: str) -> Queue:
    if db not in _ingest_queues:
        _ingest_queues[db] = multiprocessing.Queue()
    return _ingest_queues[db]


def _ingest_worker(db: str, generator_config: GeneratorConfig, queue: Queue):
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


def start_ingest_worker(db: str, generator_config: GeneratorConfig) -> Tuple[Queue, Process]:
    queue = get_ingest_queue(db)
    process = multiprocessing.Process(target=_ingest_worker, args=(db, generator_config, queue))
    process.start()
    return queue, process
