import atexit
import faulthandler
import json
import logging
import multiprocessing
import os
import re
import signal
from pathlib import Path
from typing import Tuple

import persistqueue
from haystack import Pipeline, Document
from persistqueue import Empty

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import build_ingest_pipeline, build_doc_type_pipeline
from shyhurricane.task_queue import TaskPool

logger = logging.getLogger(__name__)


def _get_queue(db: str, queue_name: str) -> persistqueue.SQLiteAckQueue:
    if os.path.exists("/data"):
        # Running inside a container
        path = Path("/data", "queues", queue_name)
    else:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), queue_name)
    os.makedirs(path.parent, mode=0o755, exist_ok=True)
    return persistqueue.SQLiteAckQueue(path=str(path), auto_commit=True)


def get_ingest_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return _get_queue(db, "ingest_queue")


def _get_doc_type_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return _get_queue(db, "doc_type_queue")


def _ingest_worker(db: str):
    try:
        faulthandler.register(signal.SIGUSR1)
        logger.info(f"Index worker starting in PID {os.getpid()}")

        queue = get_ingest_queue(db)
        atexit.register(queue.close)
        doc_type_queue = _get_doc_type_queue(db)
        atexit.register(doc_type_queue.close)

        pipeline: Pipeline = build_ingest_pipeline(db=db)
        count = 0
        logger.info(f"Index worker ready in PID {os.getpid()}")
        while True:
            if count % 1000 == 999:
                logger.info("Shrinking index queue")
                try:
                    queue.clear_acked_data(max_delete=1000, keep_latest=0)
                    queue.shrink_disk_usage()
                except Exception as e:
                    logger.debug("Shrinking index queue failed: %s", e)

            try:
                item = queue.get(block=False, timeout=2)
            except Empty:
                continue
            count += 1
            if item is None:
                queue.ack(item)
                continue
            logger.info(f"Processing {item[0:128]} in PID {os.getpid()}")
            try:
                output = pipeline.run({"input_router": {"text": str(item)}})

                for doc in output.get("output", {}).get("documents", []):
                    if doc.meta.get("type") == "content":
                        doc_type_queue.put(doc)

                queue.ack(item)
            except Exception as e:
                queue.ack_failed(item)
                url = None
                try:
                    url = json.loads(item).get("request", {}).get("endpoint", None)
                except Exception as e:
                    pass
                logger.error(f"Error in ingestion pipeline for {url} {len(item)} bytes, {e}:\n{item[0:1024]} ...",
                             exc_info=e)
    except KeyboardInterrupt:
        pass
    logger.info(f"Index worker finished in PID {os.getpid()}")


def _doc_type_worker(db: str, generator_config: GeneratorConfig):
    try:
        faulthandler.register(signal.SIGUSR1)
        logger.info(f"Document specific index worker starting in PID {os.getpid()}")

        doc_type_queue = _get_doc_type_queue(db)
        atexit.register(doc_type_queue.close)

        pipeline: Pipeline = build_doc_type_pipeline(db=db, generator_config=generator_config)

        count = 0
        logger.info(f"Document specific index worker ready in PID {os.getpid()}")
        while True:
            if count % 100 == 99:
                logger.info("Shrinking doc_type queue")
                try:
                    doc_type_queue.clear_acked_data(max_delete=1000, keep_latest=0)
                    doc_type_queue.shrink_disk_usage()
                except Exception as e:
                    logger.debug("Shrinking doc_type queue failed: %s", e)

            try:
                item: Document = doc_type_queue.get(block=False, timeout=2)
            except Empty:
                continue
            count += 1
            if item is None:
                doc_type_queue.ack(item)
                continue
            logger.info(f"Processing document {item.id} in PID {os.getpid()}")
            try:
                pipeline.run({"input": {"documents": [item]}})
                doc_type_queue.ack(item)
            except Exception as e:
                doc_type_queue.ack_failed(item)
                url = item.meta.get("url", "???")
                logger.error(f"Error in document specific pipeline for {url}, {item.id}, {e}", exc_info=e)
    except KeyboardInterrupt:
        pass
    logger.info(f"Document specific index worker finished in PID {os.getpid()}")


def start_ingest_worker(db: str, generator_config: GeneratorConfig, pool_size: int = 1) -> Tuple[
    persistqueue.SQLiteAckQueue, TaskPool]:
    queue = get_ingest_queue(db)
    processes = []
    for idx in range(pool_size):
        # these processes are heavy-weight
        process = multiprocessing.Process(target=_doc_type_worker, args=(db, generator_config))
        process.start()
        processes.append(process)

    # this is a light-weight process, we only need one
    ingest_process = multiprocessing.Process(target=_ingest_worker, args=(db,))
    ingest_process.start()
    processes.append(ingest_process)

    return queue, TaskPool(processes)
