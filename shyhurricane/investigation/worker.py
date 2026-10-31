"""Restartable background materialization without models or target requests."""

import asyncio
import logging
import multiprocessing
import sqlite3
import time

from qdrant_client.http import models as qm

from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.retry_policy import transient_neo4j_error
from shyhurricane.investigation.engine import artifact_hash_verifier, correlate, correlation_query
from shyhurricane.investigation.rules import aggregate_hotspot, derive
from shyhurricane.investigation.storage import CorrelationStore
from shyhurricane.task_queue.types import prepare_worker_process

logger = logging.getLogger(__name__)


def graph_revision(graph):
    rows = graph.read(
        "MATCH (n:GraphState {id:'publication_revision'}) RETURN coalesce(n.value,0) AS revision", timeout=5
    )
    return rows[0]["revision"] if rows else 0


async def reconcile(store, client):
    """One vector-free page per slice; persist the source cursor only after its handoffs."""
    from shyhurricane.task_queue.finding_worker import FINDING_VERSION

    if time.time() < store.setting("reconcile_after", 0):
        return
    points, offset = await client.scroll(
        collection_name="finding",
        scroll_filter=qm.Filter(
            must=[
                qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=FINDING_VERSION)),
            ]
        ),
        offset=store.setting("reconcile_offset"),
        limit=100,
        with_payload=[
            "id",
            "meta.url",
            "meta.title",
            "meta.netloc",
            "meta.host",
            "meta.finding_metadata",
            "meta.finding_metadata_conflicts",
            "meta.finding_metadata_revision",
        ],
        with_vectors=False,
    )
    for point in points:
        payload = point.payload or {}
        metadata = payload.get("meta", {})
        target = metadata.get("url") or metadata.get("netloc") or metadata.get("host")
        if not target:
            continue
        finding_id = payload.get("id") or str(point.id).replace("-", "")
        store.submit(
            finding_id,
            target,
            metadata.get("finding_metadata", {}),
            metadata.get("finding_metadata_conflicts", []),
            metadata.get("finding_metadata_revision", 1),
            title=metadata.get("title", ""),
        )
    store.set_setting("reconcile_offset", offset)
    if offset is None:
        store.set_setting("reconcile_after", time.time() + 60)
        store.set_setting("reconcile_complete", True)
        store.set_setting("last_reconciliation", time.time())


def materialize_one(store, graph, artifacts, revision):
    job = store.next_job(revision)
    if job is None:
        return False
    try:
        if job["kind"] == "hotspot":
            members, limited, waiting = store.hotspot_members(job["id"], revision)
            candidate = aggregate_hotspot(job["id"], members, limited=limited)
            store.publish_derived(job, [candidate] if candidate else [], waiting=waiting)
        elif job["kind"] == "derive":
            result = store.load_result(job["id"])
            if result is None:
                store.publish_derived(job, [], waiting=True)
            else:
                neighbors, limited = store.neighbors(result.get("pairing_keys", result.get("association_keys", [])))
                candidates = derive(result, neighbors, include_hotspots=False)
                if limited:
                    for candidate in candidates:
                        candidate["contexts_limited"] = True
                        candidate["analysis_gaps"].append("Related finding selection limited to 100 neighbors or keys")
                store.publish_derived(job, candidates, dependency=result, limited=limited)
        else:
            result = correlate(
                job, correlation_query(graph, revision), revision, verify_hash=artifact_hash_verifier(artifacts)
            )
            if len(result.get("pairing_keys", [])) > 100:
                result["contexts_limited"] = True
                result["analysis_gaps"].append("Related finding lookup limited to 100 keys")
            store.publish(job, result, revision)
        logger.info("Investigation refreshed kind=%s key=%s revision=%s", job["kind"], job["id"], revision)
    except Exception as error:
        transient = isinstance(error, (TimeoutError, OSError, sqlite3.OperationalError)) or transient_neo4j_error(error)
        store.failed(job, error, transient=transient)
        logger.warning(
            "Investigation failed finding=%s error=%s transient=%s", job["id"], type(error).__name__, transient
        )
    return True


async def run_worker(db, location, health_state, stop_event):
    from shyhurricane.db import create_qdrant_client
    from shyhurricane.graph.artifacts import ArtifactStore

    store = CorrelationStore(db)
    graph = GraphStore(location)
    client = None
    artifacts = None
    try:
        client = await create_qdrant_client(db)
        artifacts = ArtifactStore(db)
        while not stop_event.is_set():
            if not health_state.is_set():
                stop_event.wait(1)
                continue
            try:
                revision = graph_revision(graph)
                store.set_setting("graph_revision", revision)
                await reconcile(store, client)
                store.set_setting("worker_error", None)
                # Recheck health and publication revision between bounded finding jobs.
                worked = materialize_one(store, graph, artifacts, revision)
                if not worked:
                    stop_event.wait(1)
            except Exception as error:
                store.set_setting("worker_error", type(error).__name__)
                logger.warning("Investigation worker deferred error=%s", type(error).__name__)
                stop_event.wait(5)
    finally:
        if artifacts is not None:
            artifacts.close()
        if client is not None:
            await client.close()
        graph.close()
        store.close()


def investigation_worker(db, location, health_state, stop_event):
    prepare_worker_process()
    asyncio.run(run_worker(db, location, health_state, stop_event))


def start_investigation_worker(db, location, health_state, stop_event):
    process = multiprocessing.Process(target=investigation_worker, args=(db, location, health_state, stop_event))
    process._shyhurricane_monitor_process_group = True
    process.start()
    return process
