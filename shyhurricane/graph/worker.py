"""Durable graph consumption and offline backfill share the same publication path."""

import logging
import multiprocessing
import time

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.continuations import Continuations
from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.policy import ANALYZER_VERSION
from shyhurricane.graph.publication import PublicationConflict
from shyhurricane.graph.queue_receipts import QueueReceipts
from shyhurricane.graph.retry_policy import transient_neo4j_error
from shyhurricane.graph.scheduling import MAX_RECONCILE_CAPTURES, ReanalysisScheduler
from shyhurricane.index.javascript_analysis import javascript_url_from_map
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_get
from shyhurricane.task_queue.types import prepare_worker_process

logger = logging.getLogger(__name__)


def complete_capture(artifacts, scheduler, event, mode, item):
    logger.info("Graph capture %s stage=reconcile starting", event["id"])
    # A newly arrived target can resolve references regardless of ingest order.
    chain = set(event.get("reconcile_chain", [])) | {event["id"]}
    remaining = event.get("reconcile_remaining", max(0, MAX_RECONCILE_CAPTURES - len(chain)))
    seen = set(chain)
    if not event.get("reconcile") and remaining > 0:
        urls = [event["data"]["url"]]
        bundle = javascript_url_from_map(urls[0])
        if bundle:
            urls.append(bundle)
        for url in urls:
            for dependent in artifacts.dependents(url):
                if dependent["id"] != event["id"] and dependent["id"] not in seen:
                    scheduler.request(dependent["id"], chain, remaining - 1)
                    seen.add(dependent["id"])
    headers = {key.lower(): value for key, value in event["data"].get("response_headers", {}).items()}
    mime = headers.get("content-type", "")
    if remaining > 0 and ("html" in mime or "javascript" in mime):
        for target in artifacts.targets(event["id"]):
            if target["id"] not in seen:
                scheduler.request(target["id"], chain, remaining - 1)
                seen.add(target["id"])
    scheduler.flush()
    record_completion(artifacts, scheduler, event, mode, item)


def record_completion(artifacts, scheduler, event, mode, item):
    with artifacts.connection:
        artifacts.connection.execute(
            "UPDATE analysis_policies SET completed_version=?,completed_mode=? WHERE capture_id=?",
            (ANALYZER_VERSION, mode, event["id"]),
        )
    artifacts.status(event["id"], "complete")
    if "reanalysis_ticket" in item:
        scheduler.finish(item)


def graph_worker(db, location, health_state, stop_event, open_world):
    prepare_worker_process()
    queue = get_persistent_queue(db, "graph_queue", auto_resume=False)
    queue.resume_unack_tasks()
    artifacts = ArtifactStore(db)
    store = GraphStore(location)
    from shyhurricane.index.web_resources import _wait_for_health

    try:
        continuations = Continuations(artifacts)
        continuations.recover()
        receipts = QueueReceipts(artifacts.connection, queue)
        receipts.recover()
        scheduler = ReanalysisScheduler(artifacts, queue)
        scheduler.recover()

        def continuation_item():
            key = continuations.ready()
            return {"graph_continuation": key} if key else None

        items = iter(persistent_queue_get(queue, stop_event=stop_event, idle_callback=continuation_item, raw=True))
        continuation_turn = False
        while _wait_for_health(health_state, stop_event):
            scheduler.flush()
            item = continuation_item() if continuation_turn else None
            if item is None:
                try:
                    item = next(items)
                except StopIteration:
                    item = continuation_item()
                    if item is None:
                        break
            if "graph_continuation" in item:
                if not health_state.is_set():
                    continue
                continuation_turn = False
                key = item["graph_continuation"]
                completed = continuations.step(key, store, extractor=extract)
                if completed is not None:
                    try:
                        if continuations.reconcile(key, completed, scheduler):
                            record_completion(artifacts, scheduler, completed["event"],
                                              completed["projection"]["library_analysis"], completed["item"])
                            continuations.finish(key, completed)
                            receipts.settle(key, failed=False)
                        else:
                            continuations.save(key, completed)
                    except Exception as error:
                        if transient_neo4j_error(error):
                            continuations.retry(key, completed, error)
                        else:
                            continuations.save(key, completed, status="failed", error=str(error))
                            artifacts.status(completed["event"]["id"], "failed", str(error))
                            if "reanalysis_ticket" in completed["item"]:
                                scheduler.retry(completed["item"], failed=True)
                            receipts.settle(key, failed=True)
                        logger.warning("Graph continuation reconciliation retained %s", key, exc_info=True)
                elif continuations.connection.execute(
                    "SELECT state FROM graph_continuations WHERE id=?", (key,)
                ).fetchone()[0] == "failed":
                    capture_id, ticket = continuations.connection.execute(
                        "SELECT capture_id,ticket FROM graph_continuations WHERE id=?", (key,)
                    ).fetchone()
                    if ticket:
                        scheduler.retry({"id": capture_id, "reanalysis_ticket": ticket}, failed=True)
                    receipts.settle(key, failed=True)
                continue
            receipt = item
            item = receipt["data"] if "pqid" in receipt else receipt
            continuation_turn = True
            if not health_state.is_set():
                queue.nack(receipt)
                continue
            try:
                active = None
                if "reanalysis_ticket" in item:
                    active = artifacts.connection.execute(
                        "SELECT id FROM graph_continuations WHERE capture_id=? AND ticket=? "
                        "AND state IN ('pending','running') LIMIT 1",
                        (item["id"], item["reanalysis_ticket"]),
                    ).fetchone()
                event = (continuations.load(active[0])["event"] if active else
                         scheduler.claim(item) if "reanalysis_ticket" in item else item)
                if event is None:
                    queue.ack(receipt)
                    continue
                policy = artifacts.connection.execute(
                    "SELECT mode FROM analysis_policies WHERE capture_id=?", (event["id"],)
                ).fetchone()
                if policy:
                    event = {**event, "library_analysis": policy[0]}
                if continuations.eligible(event):
                    key = continuations.enqueue(event, item, open_world and not policy)
                    state = artifacts.connection.execute(
                        "SELECT state FROM graph_continuations WHERE id=?", (key,)
                    ).fetchone()[0]
                    # Failed rows without outstanding receipts are explicit failed-queue redeliveries.
                    if state == "failed" and not receipts.contains(key):
                        continuations.save(key, continuations.load(key))
                        state = "pending"
                    receipts.track(key, receipt)
                    artifacts.status(event["id"], {
                        "done": "complete", "superseded": "complete", "failed": "failed"
                    }.get(state, "processing"))
                    if state in {"done", "failed", "superseded"}:
                        receipts.settle(key, failed=state == "failed")
                    continue
                started = time.monotonic()
                logger.info("Graph capture %s stage=extract starting", event["id"])
                artifacts.status(event["id"], "processing")
                projection = extract(event, artifacts, open_world=open_world and not policy)
                logger.info(
                    "Graph capture %s stage=extract finished entities=%s relationships=%s gaps=%s seconds=%.3f",
                    event["id"],
                    len(projection.nodes),
                    len(projection.edges),
                    len(projection.gaps),
                    time.monotonic() - started,
                )
                store.publish(projection)
                complete_capture(artifacts, scheduler, event, projection.library_analysis, item)
                queue.ack(receipt)
                logger.info("Graph capture %s acknowledged seconds=%.3f", event["id"], time.monotonic() - started)
            except PublicationConflict as error:
                logger.warning(
                    "Graph publication changed while staging capture %s; retaining work: %s", item["id"], error
                )
                if "reanalysis_ticket" in item:
                    scheduler.retry(item)
                queue.nack(receipt)
            except Exception as error:
                if transient_neo4j_error(error):
                    artifacts.status(item["id"], "pending", str(error))
                    if "reanalysis_ticket" in item:
                        scheduler.retry(item)
                    queue.nack(receipt)
                    health_state.clear()
                    store.close()
                    logger.warning("Transient Neo4j failure; graph capture %s pending retry: %s", item["id"], error)
                    continue
                # Terminal failures require explicit retry, never acknowledgement as success.
                queue.ack_failed(receipt)
                artifacts.status(item["id"], "failed", str(error))
                if "reanalysis_ticket" in item:
                    scheduler.retry(item, failed=True)
                logger.exception("Graph storage or analysis failed for %s", item["id"])
    except Exception:
        logger.exception("Graph worker stopped; durable graph work retained for startup recovery")
        raise
    finally:
        store.close()
        artifacts.close()
        queue.close()


def start_graph_worker(db, location, health_state, stop_event, open_world):
    process = multiprocessing.Process(target=graph_worker, args=(db, location, health_state, stop_event, open_world))
    process._shyhurricane_monitor_process_group = True
    process.start()
    return process
