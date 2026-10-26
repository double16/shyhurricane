"""Consume graph inputs into durable, finite analysis epochs."""

import logging
import multiprocessing

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.epochs import Epochs
from shyhurricane.graph.rebuild import flush_rebuild_requests
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_get
from shyhurricane.task_queue.types import prepare_worker_process

logger = logging.getLogger(__name__)


def graph_worker(db, location, health_state, stop_event, open_world):
    prepare_worker_process()
    queue = get_persistent_queue(db, "graph_queue", auto_resume=False)
    artifacts = ArtifactStore(db)
    store = GraphStore(location)
    epochs = None
    from shyhurricane.index.web_resources import _wait_for_health

    try:
        # Validate legacy state before reclaiming deliveries or doing any graph writes.
        epochs = Epochs(artifacts, store, open_world=open_world, isolate=True)
        flush_rebuild_requests(artifacts, queue)
        queue.resume_unack_tasks()
        epochs.settle(queue)

        def available():
            return {"graph_epoch": True} if epochs.available() else None

        items = persistent_queue_get(queue, stop_event=stop_event, idle_callback=available, raw=True)
        while _wait_for_health(health_state, stop_event):
            try:
                receipt = next(items)
            except StopIteration:
                break
            if "graph_epoch" not in receipt:
                if not health_state.is_set():
                    queue.nack(receipt)
                    continue
                try:
                    epochs.accept(receipt["data"], receipt["pqid"])
                    with queue.action_lock:
                        queue._unack_cache.pop(receipt["pqid"], None)
                except Exception:
                    queue.ack_failed(receipt)
                    logger.exception("Graph epoch input rejected; delivery retained for explicit retry")
            if health_state.is_set():
                epochs.step()
                epochs.settle(queue)
    except Exception:
        logger.exception("Graph worker stopped; durable graph work retained for startup recovery")
        raise
    finally:
        if epochs is not None:
            epochs.close()
        store.close()
        artifacts.close()
        queue.close()


def start_graph_worker(db, location, health_state, stop_event, open_world):
    process = multiprocessing.Process(target=graph_worker, args=(db, location, health_state, stop_event, open_world))
    process._shyhurricane_monitor_process_group = True
    process.start()
    return process
