import atexit
import faulthandler
import json
import logging
import multiprocessing
import os
import signal
from typing import Tuple

import persistqueue
from haystack import Pipeline

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import build_ingest_pipeline, build_doc_type_pipeline
from shyhurricane.mcp_server.server_config import get_server_config
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_get
from shyhurricane.task_queue import TaskPool
from shyhurricane.utils import get_log_path

logger = logging.getLogger(__name__)


def get_ingest_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "ingest_queue")


def get_doc_type_queue(db: str) -> persistqueue.SQLiteAckQueue:
    return get_persistent_queue(db, "doc_type_queue")


def _ingest_worker(db: str):
    try:
        faulthandler.register(signal.SIGUSR1)
        logger.info(f"Index worker starting in PID {os.getpid()}")

        queue = get_ingest_queue(db)
        atexit.register(queue.close)
        queue.resume_unack_tasks()

        doc_type_queue = get_doc_type_queue(db)
        atexit.register(doc_type_queue.close)

        index_log_path = get_log_path(db, "index.txt")

        pipeline: Pipeline = build_ingest_pipeline(db=db)
        logger.info(f"Index worker ready in PID {os.getpid()}")
        for item in persistent_queue_get(queue, shrink_count=1000):
            logger.info(f"Processing {item[0:128]} in PID {os.getpid()}")

            if index_log_path is not None:
                try:
                    with open(index_log_path, "a") as index_log:
                        index_log.write(item)
                        index_log.write("\n")
                except Exception as e:
                    logger.error("Failed to write index log at %s: %s", index_log_path, e)
                    index_log_path = None

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
                except Exception:
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

        doc_type_queue = get_doc_type_queue(db)
        atexit.register(doc_type_queue.close)
        doc_type_queue.resume_unack_tasks()

        pipeline: Pipeline = build_doc_type_pipeline(db=db, generator_config=generator_config)

        logger.info(f"Document specific index worker ready in PID {os.getpid()}")
        for item in persistent_queue_get(doc_type_queue, shrink_count=100):
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

    processes = []

    if get_server_config().low_power:
        logger.warning(
            "low_power: disabling document type specific indexing, but still queuing (run with '--low-power false' to process)")
    else:
        for idx in range(pool_size):
            # these processes are heavy-weight
            process = multiprocessing.Process(target=_doc_type_worker, args=(db, generator_config))
            process.start()
            processes.append(process)

    # this is a light-weight process, we only need one
    ingest_process = multiprocessing.Process(target=_ingest_worker, args=(db,))
    ingest_process.start()
    processes.append(ingest_process)

    queue = get_ingest_queue(db)
    return queue, TaskPool(processes)
