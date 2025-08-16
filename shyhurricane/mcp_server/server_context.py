import atexit
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from multiprocessing import Queue
from typing import Optional, Dict, List

import chromadb
import persistqueue
from haystack import Pipeline
from haystack_integrations.document_stores.chroma import ChromaDocumentStore

from shyhurricane.index.web_resources_pipeline import build_stores
from shyhurricane.server_config import get_server_config
from shyhurricane.index.web_resources import start_ingest_worker
from shyhurricane.mcp_server.generator_config import get_generator_config
from shyhurricane.retrieval_pipeline import create_chroma_client, build_document_pipeline, \
    build_website_context_pipeline
from shyhurricane.task_queue import start_task_worker, TaskPool
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)


@dataclass
class ServerContext:
    db: str
    cache_path: str
    document_pipeline: Optional[Pipeline]
    """
    Processes retrieval of documents using embeddings. May be None when in low power mode.
    """
    website_context_pipeline: Optional[Pipeline]
    """
    Determines the context of the query to `document_pipeline` using an LLM. May be None when in low power mode.
    """
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
    seclists_volume: str
    open_world: bool = True
    commands: Optional[List[str]] = None
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


async def get_server_context() -> ServerContext:
    global _server_context
    if _server_context is None:
        server_config = get_server_config()
        db = os.environ.get('CHROMA', '127.0.0.1:8200')
        logger.info("Using chroma database at %s", db)
        cache_path: str = os.path.join(os.environ.get('TOOL_CACHE', os.environ.get('TMPDIR', '/tmp')), 'tool_cache')
        os.makedirs(cache_path, exist_ok=True)
        disable_elicitation = bool(os.environ.get('DISABLE_ELICITATION', 'False'))
        chroma_client = await create_chroma_client(db=db)

        for retry in reversed(range(3)):
            try:
                subprocess.check_call(["docker", "volume", "inspect", "mcp_session"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                try:
                    subprocess.check_call(["docker", "volume", "create", "mcp_session"],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    break
                except subprocess.CalledProcessError as e:
                    if retry == 0:
                        logger.error("Failed to create mcp_session volume", exc_info=e)
                        sys.exit(1)
                    else:
                        time.sleep(5)
        try:
            subprocess.check_call(["docker", "volume", "inspect", "seclists"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            try:
                # make sure the image is available first
                subprocess.check_call(["docker", "image", "ls", unix_command_image()],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # try to create the volume
                subprocess.check_call(["docker", "volume", "create", "seclists"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Populating seclists volume")
                subprocess.Popen(
                    ["docker", "run", "--user=0", "--rm", "-d", "-v", "seclists:/usr/share/seclists",
                     unix_command_image(), "/bin/bash", "-c",
                     "git clone --depth=1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists && "
                     "tar -xf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/seclists/Passwords/Leaked-Databases/ && "
                     "chmod a+r /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
                     "/usr/share/seclists"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.error("Failed to create seclists volume", exc_info=e)
                sys.exit(1)

        if server_config.low_power:
            logger.warning("low_power: skipping embedding based retrieval pipelines")
            document_pipeline = None
            website_context_pipeline = None
            stores = build_stores(db)
        else:
            document_pipeline, _, stores = await build_document_pipeline(
                db=db,
                generator_config=get_generator_config(),
            )
            website_context_pipeline = build_website_context_pipeline(
                generator_config=get_generator_config(),
            )

        ingest_queue, ingest_pool = start_ingest_worker(db=db, generator_config=get_generator_config(),
                                                        pool_size=server_config.ingest_pool_size)
        task_worker_ipc = start_task_worker(db, ingest_queue.path, server_config.task_pool_size)

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
            seclists_volume="seclists",
            disable_elicitation=disable_elicitation,
            open_world=server_config.open_world,
        )

    return _server_context


@atexit.register
def close_server_context() -> None:
    global _server_context
    if _server_context is not None:
        _server_context.close()
        _server_context = None
