import atexit
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from multiprocessing import Queue
from typing import Optional, Dict

import chromadb
import persistqueue
from haystack import Pipeline
from haystack_integrations.document_stores.chroma import ChromaDocumentStore

from shyhurricane.index.web_resources import start_ingest_worker
from shyhurricane.mcp_server.generator_config import get_generator_config
from shyhurricane.retrieval_pipeline import create_chroma_client, build_document_pipeline, \
    build_website_context_pipeline
from shyhurricane.task_queue import start_task_worker, TaskPool

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    task_pool_size: int = 3
    ingest_pool_size: int = 1


_server_config: ServerConfig = ServerConfig()


@dataclass
class ServerContext:
    db: str
    cache_path: str
    document_pipeline: Pipeline
    website_context_pipeline: Pipeline
    ingest_queue: persistqueue.SQLiteAckQueue
    ingest_pool: TaskPool
    task_queue: Queue
    task_pool: TaskPool
    spider_result_queue: Queue
    port_scan_result_queue: Queue
    dir_busting_result_queue: Queue
    stores: Dict[str, ChromaDocumentStore]
    chroma_client: chromadb.AsyncClientAPI
    mcp_session_volume: str
    disable_elicitation: bool = False

    def close(self):
        logger.info("Terminating task pool")
        self.task_pool.close()
        logger.info("Terminating ingest pool")
        self.ingest_pool.close()
        logger.info("Closing queues ...")
        for q in [self.ingest_queue, self.task_queue, self.spider_result_queue, self.port_scan_result_queue]:
            try:
                q.put(None)
                q.close()
            except Exception:
                pass
        logger.info("ServerContext closed")


_server_context: Optional[ServerContext] = None


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


async def get_server_context() -> ServerContext:
    global _server_context
    if _server_context is None:
        db = os.environ.get('CHROMA', '127.0.0.1:8200')
        logger.info("Using chroma database at %s", db)
        cache_path: str = os.path.join(os.environ.get('TOOL_CACHE', os.environ.get('TMPDIR', '/tmp')), 'tool_cache')
        os.makedirs(cache_path, exist_ok=True)
        disable_elicitation = bool(os.environ.get('DISABLE_ELICITATION', 'False'))
        chroma_client = await create_chroma_client(db=db)
        document_pipeline, retrievers, stores = await build_document_pipeline(
            db=db,
            generator_config=get_generator_config(),
        )
        website_context_pipeline = build_website_context_pipeline(
            generator_config=get_generator_config(),
        )
        ingest_queue, ingest_pool = start_ingest_worker(db=db, generator_config=get_generator_config(),
                                                        pool_size=_server_config.ingest_pool_size)
        task_worker_ipc = start_task_worker(db, ingest_queue.path, _server_config.task_pool_size)

        for retry in reversed(range(3)):
            try:
                subprocess.check_call(["docker", "volume", "inspect", "mcp_session"], stdout=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                try:
                    subprocess.check_call(["docker", "volume", "create", "mcp_session"], stdout=subprocess.DEVNULL)
                    break
                except subprocess.CalledProcessError as e:
                    if retry == 0:
                        raise e
                    else:
                        time.sleep(5)

        _server_context = ServerContext(
            db=db,
            cache_path=cache_path,
            document_pipeline=document_pipeline,
            website_context_pipeline=website_context_pipeline,
            ingest_queue=ingest_queue,
            ingest_pool=ingest_pool,
            task_queue=task_worker_ipc.task_queue,
            task_pool=task_worker_ipc.task_pool,
            spider_result_queue=task_worker_ipc.spider_result_queue,
            port_scan_result_queue=task_worker_ipc.port_scan_result_queue,
            dir_busting_result_queue=task_worker_ipc.dir_busting_result_queue,
            stores=stores,
            chroma_client=chroma_client,
            mcp_session_volume="mcp_session",
            disable_elicitation=disable_elicitation,
        )

    return _server_context


@atexit.register
def close_server_context() -> None:
    global _server_context
    if _server_context is not None:
        _server_context.close()
        _server_context = None
