import atexit
import faulthandler
import logging
import multiprocessing
import os
import signal
from multiprocessing import Queue, Process

import persistqueue

from shyhurricane.embedder_cache import EmbedderCache
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.persistent_queue import get_doc_type_queue
from shyhurricane.mcp_server.generator_config import get_generator_config
from shyhurricane.task_queue.dir_busting_worker import dir_busting_worker
from shyhurricane.task_queue.finding_worker import save_finding_worker, FindingContext
from shyhurricane.task_queue.port_scan_worker import port_scan_worker, PortScanContext
from shyhurricane.task_queue.spider_worker import spider_worker
from shyhurricane.task_queue.types import SpiderQueueItem, PortScanQueueItem, TaskWorkerIPC, DirBustingQueueItem, \
    TaskPool, SaveFindingQueueItem

logger = logging.getLogger(__name__)


def start_task_worker(db: str, ingest_queue_path: str, pool_size: int = 1) -> TaskWorkerIPC:
    assert pool_size > 0
    task_queue = multiprocessing.Queue()
    spider_result_queue = multiprocessing.Queue()
    port_scan_result_queue = multiprocessing.Queue()
    dir_busting_result_queue = multiprocessing.Queue()
    processes = []
    for idx in range(pool_size):
        proc = Process(target=_task_router, kwargs={
            "db": db,
            "ingest_queue_path": ingest_queue_path,
            "task_queue": task_queue,
            "spider_result_queue": spider_result_queue,
            "port_scan_result_queue": port_scan_result_queue,
            "dir_busting_result_queue": dir_busting_result_queue,
            "generator_config": get_generator_config(),
        })
        proc.start()
        processes.append(proc)
    return TaskWorkerIPC(
        task_queue=task_queue,
        spider_result_queue=spider_result_queue,
        port_scan_result_queue=port_scan_result_queue,
        dir_busting_result_queue=dir_busting_result_queue,
        task_pool=TaskPool(processes),
    )


def _task_router(db: str,
                 ingest_queue_path: str,
                 task_queue: Queue,
                 spider_result_queue: Queue,
                 port_scan_result_queue: Queue,
                 dir_busting_result_queue: Queue,
                 generator_config: GeneratorConfig,
                 ):
    try:
        faulthandler.register(signal.SIGUSR1)
        logger.info(f"Starting task router in PID {os.getpid()}")

        embedder_cache = EmbedderCache()

        ingest_queue = persistqueue.SQLiteAckQueue(path=ingest_queue_path, auto_commit=True)
        atexit.register(ingest_queue.close)

        doc_type_queue = get_doc_type_queue(db)
        atexit.register(doc_type_queue.close)

        port_scan_ctx = None
        finding_ctx = None

        while True:
            item = task_queue.get()
            logger.info(f"Processing {item.__class__.__name__} in PID {os.getpid()}")
            try:
                if isinstance(item, SpiderQueueItem):
                    spider_worker(item, ingest_queue, spider_result_queue)

                elif isinstance(item, PortScanQueueItem):
                    if port_scan_ctx is None:
                        port_scan_ctx = PortScanContext(db=db, embedder_cache=embedder_cache)
                        port_scan_ctx.warm_up()
                    port_scan_worker(port_scan_ctx, item, port_scan_result_queue)

                elif isinstance(item, DirBustingQueueItem):
                    dir_busting_worker(item, ingest_queue, dir_busting_result_queue)

                elif isinstance(item, SaveFindingQueueItem):
                    if finding_ctx is None:
                        finding_ctx = FindingContext(
                            db=db,
                            generator_config=generator_config,
                            embedder_cache=embedder_cache,
                            doc_type_queue=doc_type_queue)
                        finding_ctx.warm_up()
                    save_finding_worker(finding_ctx, item)

            except KeyboardInterrupt:
                break
            except BaseException as e:
                logger.error(f"Error running {item.__class__.__name__} in PID {os.getpid()}", exc_info=e)

    except KeyboardInterrupt:
        pass
    logger.info(f"Finished task router in PID {os.getpid()}")
