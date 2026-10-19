import asyncio
import atexit
import logging
import multiprocessing
import os
import subprocess
import time
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import TYPE_CHECKING, Dict, List, Optional

import persistqueue
from haystack import Pipeline
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client import AsyncQdrantClient

from shyhurricane.data_paths import configure_data_dir, state_path
from shyhurricane.db import create_qdrant_client, create_qdrant_document_store, qdrant_host_port
from shyhurricane.disk_space import DiskSpaceGuard
from shyhurricane.doc_type_model_map import doc_type_to_model
from shyhurricane.graph.database import GraphStore, graph_location
from shyhurricane.graph.maintenance import GraphMaintenance
from shyhurricane.haystack_lifecycle import close_haystack_resources
from shyhurricane.health import HealthMonitor, qdrant_probe
from shyhurricane.mcp_server.generator_config import get_generator_config
from shyhurricane.persistent_queue import AsyncIngestWriter, cleanup_persistent_queues_on_startup
from shyhurricane.result_pages import ResultPageStore
from shyhurricane.retrieval_pipeline import build_document_pipeline, build_website_context_pipeline
from shyhurricane.server_config import get_server_config
from shyhurricane.utils import get_log_timestamp, unix_command_image

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from shyhurricane.task_queue.types import TaskPool


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
    ingest_pool: "TaskPool"
    task_queue: Queue
    task_pool: "TaskPool"
    spider_result_queue: Queue
    port_scan_result_queue: Queue
    dir_busting_result_queue: Queue
    stores: Dict[str, QdrantDocumentStore]
    qdrant_client: AsyncQdrantClient
    mcp_session_volume: str
    qdrant_host: Optional[str] = None
    qdrant_port: Optional[int] = None
    open_world: bool = True
    commands: Optional[List[str]] = None
    disable_elicitation: bool = False
    proxy_host: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_ca_cert_path: Optional[os.PathLike] = None
    health_monitor: Optional[HealthMonitor] = None
    low_power: bool = False
    indexing_enabled: Optional[object] = None
    worker_manager: Optional[object] = None
    stop_event: Optional[object] = None
    result_store: ResultPageStore | None = None
    graph_store: GraphStore | None = None
    graph_maintenance: GraphMaintenance | None = None
    _closed: bool = field(default=False, init=False)
    _ingest_writer: AsyncIngestWriter | None = field(default=None, init=False)

    async def enqueue_ingest(self, item) -> None:
        if self._closed:
            raise RuntimeError("Server is shutting down")
        if self._ingest_writer is None:
            self._ingest_writer = AsyncIngestWriter(self.ingest_queue.path)
        await self._ingest_writer.put(item)

    def set_low_power(self, enabled: bool) -> None:
        self.low_power = enabled
        if self.indexing_enabled is not None:
            if enabled:
                self.indexing_enabled.clear()
            else:
                self.indexing_enabled.set()

    async def ensure_retrieval_pipelines(self) -> None:
        if self.document_pipeline is None or self.website_context_pipeline is None:
            generator_config = get_generator_config()
            # The async builder initializes synchronous providers and embedding models.
            document_pipeline, _, stores = await asyncio.to_thread(
                asyncio.run, build_document_pipeline(db=self.db, generator_config=generator_config),
            )
            website_context_pipeline = await asyncio.to_thread(
                build_website_context_pipeline, generator_config=generator_config,
            )
            self.document_pipeline = document_pipeline
            self.website_context_pipeline = website_context_pipeline
            if self.stores is not None and isinstance(self.stores, dict):
                self.stores.update(stores)
            else:
                self.stores = stores

    def close(self):
        if self._closed:
            return
        self._closed = True
        deadline = time.monotonic() + 300
        if self.stop_event is not None:
            self.stop_event.set()
        if self.graph_maintenance is not None:
            try:
                self.graph_maintenance.close(deadline)
            except Exception:
                logger.exception("Failed to close graph maintenance")
        if self._ingest_writer is not None:
            try:
                self._ingest_writer.close(timeout=max(0, deadline - time.monotonic()))
            except Exception:
                logger.exception("Failed to close ingest writer")
        if self.health_monitor is not None:
            try:
                self.health_monitor.close()
            except Exception:
                logger.exception("Failed to close health monitor")
        for pool in (self.task_pool, self.ingest_pool):
            try:
                if self.stop_event is None:
                    pool.close()
                else:
                    pool.close(deadline=deadline)
            except Exception:
                logger.exception("Failed to close worker pool")
        if self.worker_manager is not None:
            try:
                self.worker_manager.shutdown()
            except Exception:
                logger.exception("Failed to shut down worker manager")
        close_haystack_resources()
        logger.info("Closing queues ...")
        # The ingest queue is persistent. Adding a sentinel after terminating its
        # workers leaves an unprocessed active item for the next server startup.
        for q in [self.task_queue, self.spider_result_queue, self.port_scan_result_queue,
                  self.dir_busting_result_queue]:
            try:
                q.cancel_join_thread()
            except Exception:
                logger.exception("Failed to cancel queue feeder join")
            try:
                q.close()
            except Exception:
                logger.exception("Failed to close multiprocessing queue")
        try:
            self.ingest_queue.close()
        except Exception:
            pass
        if self.result_store is not None:
            self.result_store.cleanup()
        if self.graph_store is not None:
            self.graph_store.close()
        logger.info("ServerContext closed")


_server_context: Optional[ServerContext] = None


def _elicitation_disabled() -> bool:
    value = os.environ.get("DISABLE_ELICITATION", "False").strip().lower()
    return value not in {"", "false", "0", "no", "off"}


def _qdrant_readiness_probe(db: str, host: str, port: int):
    """Retry collection setup in the health thread before releasing indexing workers."""
    initialized = False

    def check() -> bool:
        nonlocal initialized
        if not qdrant_probe(host, port):
            return False
        if not initialized:
            for doc_type_model in doc_type_to_model().values():
                for collection in doc_type_model.get_qdrant_collections():
                    store = create_qdrant_document_store(db=db, index=collection)
                    try:
                        if hasattr(store, "_ensure_initialized"):
                            store._ensure_initialized()
                        else:
                            store.count_documents()
                    finally:
                        store.close()
            initialized = True
        return True

    return check


async def get_server_context() -> ServerContext:
    global _server_context
    if _server_context is not None:
        return _server_context
    from shyhurricane.index.web_resources import start_ingest_worker
    from shyhurricane.task_queue import start_task_worker

    log_timestamp = get_log_timestamp()
    server_config = get_server_config()

    configure_data_dir(server_config.data_dir)
    cache_path = str(state_path("tool_cache"))
    if os.environ.get("TOOL_CACHE"):
        cache_path = os.path.join(os.environ["TOOL_CACHE"], "tool_cache")
    os.makedirs(cache_path, exist_ok=True)
    result_store = await asyncio.to_thread(
        ResultPageStore, cache_path, int(os.environ.get("TOOL_RESULT_TTL_SECONDS", "86400")),
    )
    await asyncio.to_thread(result_store.cleanup)

    db = server_config.database
    logger.info("Using Qdrant database at %s", db)
    disable_elicitation = _elicitation_disabled()
    qdrant_client = await create_qdrant_client(db=db)
    qdrant_host, qdrant_port = qdrant_host_port(db)
    graph_store = GraphStore(graph_location())
    health_monitor = HealthMonitor(_qdrant_readiness_probe(db, qdrant_host, qdrant_port), lambda: True,
                                   neo4j_probe=graph_store.ready,
                                   disk_guard=DiskSpaceGuard(state_path("."), server_config))
    health_monitor.start()

    mcp_session_volume = os.environ.get("MCP_SESSION_VOLUME")
    if mcp_session_volume:
        subprocess.check_call(["docker", "volume", "create", mcp_session_volume],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        sessions = state_path("sessions")
        sessions.mkdir(parents=True, exist_ok=True)
        mcp_session_volume = str(sessions)

    await asyncio.create_subprocess_exec(
        "docker", "run", "--rm",
        "-v", f"{mcp_session_volume}:/work",
        unix_command_image(),
        "find", "/work", "-atime", "+2", "-not", "-ipath", "/work/.*", "-delete",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Start indexing before initializing the retrieval pipelines. Retrieval model
    # loading can take minutes, and must not stall an existing indexing backlog.
    generator_config = get_generator_config()
    worker_manager = multiprocessing.Manager()
    stop_event = multiprocessing.Event()
    indexing_enabled = worker_manager.Event()
    if not server_config.low_power:
        indexing_enabled.set()

    cleanup_persistent_queues_on_startup(db)
    ingest_queue, ingest_pool = start_ingest_worker(
        db=db,
        generator_config=generator_config,
        pool_size=server_config.ingest_pool_size,
        health_state=health_monitor.ready,
        indexing_enabled=indexing_enabled,
        log_timestamp=log_timestamp,
        stop_event=stop_event,
        open_world=server_config.open_world,
    )
    from shyhurricane.graph.worker import start_graph_worker

    ingest_pool.processes.append(start_graph_worker(db, graph_store.location, health_monitor.ready,
                                                   stop_event, server_config.open_world))
    task_worker_ipc = start_task_worker(db, ingest_queue.path, server_config.task_pool_size, log_timestamp,
                                       stop_event=stop_event)

    _server_context = ServerContext(
        db=db,
        cache_path=cache_path,
        result_store=result_store,
        graph_store=graph_store,
        document_pipeline=None,
        website_context_pipeline=None,
        ingest_queue=ingest_queue,
        ingest_pool=ingest_pool,
        task_queue=task_worker_ipc.task_queue,
        task_pool=task_worker_ipc.task_pool,
        spider_result_queue=task_worker_ipc.spider_result_queue,
        port_scan_result_queue=task_worker_ipc.port_scan_result_queue,
        dir_busting_result_queue=task_worker_ipc.dir_busting_result_queue,
        stores={},
        qdrant_client=qdrant_client,
        mcp_session_volume=mcp_session_volume,
        qdrant_host=qdrant_host,
        qdrant_port=qdrant_port,
        disable_elicitation=disable_elicitation,
        open_world=server_config.open_world,
        health_monitor=health_monitor,
        low_power=server_config.low_power,
        indexing_enabled=indexing_enabled,
        worker_manager=worker_manager,
        stop_event=stop_event,
    )
    try:
        _server_context.graph_maintenance = GraphMaintenance(
            graph_store.location, lambda: graph_store.schema_ready and health_monitor.neo4j_healthy is True,
        )
        _server_context.graph_maintenance.start()
        document_pipeline, _, stores = await build_document_pipeline(
            db=db,
            generator_config=generator_config,
        )
        _server_context.document_pipeline = document_pipeline
        _server_context.stores = stores
        _server_context.website_context_pipeline = build_website_context_pipeline(
            generator_config=generator_config,
        )
    except BaseException:
        await asyncio.to_thread(close_server_context)
        raise

    return _server_context


@atexit.register
def close_server_context() -> None:
    global _server_context
    if _server_context is not None:
        _server_context.close()
        _server_context = None
