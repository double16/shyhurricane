"""Durable graph consumption and offline backfill share the same publication path."""

import logging
import multiprocessing
import sqlite3
import time

from neo4j.exceptions import Neo4jError, ServiceUnavailable, SessionExpired

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.policy import ANALYZER_VERSION
from shyhurricane.graph.publication import PublicationConflict, PublicationMemoryError
from shyhurricane.graph.scheduling import MAX_RECONCILE_CAPTURES, ReanalysisScheduler
from shyhurricane.index.javascript_analysis import javascript_url_from_map
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_get
from shyhurricane.task_queue.types import prepare_worker_process

logger = logging.getLogger(__name__)


def graph_worker(db, location, health_state, stop_event, open_world):
    prepare_worker_process()
    queue = get_persistent_queue(db, "graph_queue", auto_resume=False)
    queue.resume_unack_tasks()
    artifacts = ArtifactStore(db)
    store = GraphStore(location)
    from shyhurricane.index.web_resources import _wait_for_health

    try:
        scheduler = ReanalysisScheduler(artifacts, queue)
        scheduler.recover()
        items = iter(persistent_queue_get(queue, stop_event=stop_event))
        while _wait_for_health(health_state, stop_event):
            scheduler.flush()
            try:
                item = next(items)
            except StopIteration:
                break
            if not health_state.is_set():
                queue.nack(item)
                continue
            try:
                event = scheduler.claim(item) if "reanalysis_ticket" in item else item
                if event is None:
                    queue.ack(item)
                    continue
                policy = artifacts.connection.execute(
                    "SELECT mode FROM analysis_policies WHERE capture_id=?", (event["id"],)
                ).fetchone()
                if policy:
                    event = {**event, "library_analysis": policy[0]}
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
                with artifacts.connection:
                    artifacts.connection.execute(
                        "UPDATE analysis_policies SET completed_version=?,completed_mode=? WHERE capture_id=?",
                        (ANALYZER_VERSION, projection.library_analysis, event["id"]),
                    )
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
                artifacts.status(event["id"], "complete")
                if "reanalysis_ticket" in item:
                    scheduler.finish(item)
                queue.ack(item)
                logger.info("Graph capture %s acknowledged seconds=%.3f", event["id"], time.monotonic() - started)
            except (ServiceUnavailable, SessionExpired, OSError, sqlite3.OperationalError) as error:
                logger.warning("Graph dependency unavailable; retaining capture %s: %s", item["id"], error)
                if "reanalysis_ticket" in item:
                    scheduler.retry(item)
                queue.nack(item)
                health_state.clear()
                store.close()
            except PublicationConflict as error:
                logger.warning(
                    "Graph publication changed while staging capture %s; retaining work: %s", item["id"], error
                )
                if "reanalysis_ticket" in item:
                    scheduler.retry(item)
                queue.nack(item)
            except PublicationMemoryError as error:
                artifacts.status(item["id"], "failed", str(error))
                if "reanalysis_ticket" in item:
                    scheduler.finish(item)
                queue.ack_failed(item)
                logger.error("Graph capture %s failed its publication memory budget: %s", item["id"], error)
            except Neo4jError as error:
                code = error.code or ""
                if error.is_retryable() or "ReadOnly" in code or ".Security." in code:
                    logger.warning("Graph capture %s retained after Neo4j error code=%s", item["id"], code)
                    if "reanalysis_ticket" in item:
                        scheduler.retry(item)
                    queue.nack(item)
                    health_state.clear()
                    store.close()
                else:
                    artifacts.status(item["id"], "failed", str(error))
                    if "reanalysis_ticket" in item:
                        scheduler.finish(item)
                    queue.ack_failed(item)
                    logger.exception("Graph publication failed for %s", item["id"])
            except Exception as error:
                artifacts.status(item["id"], "failed", str(error))
                if "reanalysis_ticket" in item:
                    scheduler.finish(item)
                queue.ack_failed(item)
                logger.exception("Graph analysis failed for %s", item["id"])
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
