import logging
import multiprocessing
from multiprocessing import Queue, Process

import persistqueue

from shyhurricane.task_queue.dir_busting_worker import dir_busting_worker
from shyhurricane.task_queue.port_scan_worker import port_scan_worker, PortScanContext
from shyhurricane.task_queue.spider_worker import spider_worker
from shyhurricane.task_queue.types import SpiderQueueItem, PortScanQueueItem, TaskWorkerIPC, DirBustingQueueItem, \
    TaskPool

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
            "dir_busting_result_queue": dir_busting_result_queue
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
                 ):
    ingest_queue = persistqueue.SQLiteQueue(path=ingest_queue_path, auto_commit=True)
    port_scan_ctx = PortScanContext(db=db)
    port_scan_ctx.warm_up()

    while True:
        item = task_queue.get()
        logger.info(item.__class__.__name__)
        if isinstance(item, SpiderQueueItem):
            try:
                spider_worker(item, ingest_queue, spider_result_queue)
            except Exception as e:
                logger.error("Error running spider", exc_info=e)
        elif isinstance(item, PortScanQueueItem):
            try:
                port_scan_worker(port_scan_ctx, item, port_scan_result_queue)
            except Exception as e:
                logger.error("Error running port scan", exc_info=e)
        elif isinstance(item, DirBustingQueueItem):
            try:
                dir_busting_worker(item, ingest_queue, dir_busting_result_queue)
            except Exception as e:
                logger.error("Error running dir busting", exc_info=e)
