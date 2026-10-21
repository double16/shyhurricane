"""Bounded, replay-safe publication with an atomic switch to a complete generation."""

import json
import logging
import time
from itertools import batched
from urllib.parse import urlsplit

from neo4j import Query, unit_of_work
from neo4j.exceptions import Neo4jError

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.lookup import context_records, reverse_host, write_contexts
from shyhurricane.graph.model import identity, projection_snapshot
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis
from shyhurricane.graph.visibility import visible_node

logger = logging.getLogger(__name__)
WRITE_BATCH_SIZE = 500
WRITE_BATCH_BYTES = 4 * 1024 * 1024
CLEANUP_GRACE_SECONDS = 300
CLEANUP_BATCHES = 10


class PublicationMemoryError(RuntimeError):
    """The smallest permitted publication operation cannot fit its memory budget."""


class PublicationConflict(RuntimeError):
    """A newer publication won the activation race; replan against current generations."""


class _BatchMemoryError(RuntimeError):
    """Prevent the driver from automatically retrying the same oversized transaction."""


def payload_batches(records):
    batch, size = [], 2
    for record in records:
        record_size = len(json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode()) + 1
        if record_size + 2 > WRITE_BATCH_BYTES:
            raise PublicationMemoryError("Graph publication record exceeds the 4 MiB payload budget")
        if batch and (len(batch) >= WRITE_BATCH_SIZE or size + record_size > WRITE_BATCH_BYTES):
            yield batch
            batch, size = [], 2
        batch.append(record)
        size += record_size
    if batch:
        yield batch


def write_batches(session, capture_id, stage, statement, parameter, records, *, deadline=None):
    """Commit each payload independently and subdivide transaction-memory failures."""

    def commit(batch):
        started = time.monotonic()

        remaining = deadline - time.monotonic() if deadline is not None else float("inf")
        if remaining <= 0:
            raise TimeoutError("Graph maintenance budget reached")

        @unit_of_work(timeout=min(graph_timeouts().write, remaining))
        def write(tx):
            try:
                tx.run(statement, **{parameter: batch}).consume()
            except Neo4jError as error:
                if (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                    raise _BatchMemoryError(str(error)) from error
                raise

        try:
            session.execute_write(write)
        except (_BatchMemoryError, Neo4jError) as error:
            if isinstance(error, Neo4jError) and not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                raise
            if len(batch) == 1:
                raise PublicationMemoryError(
                    f"Graph publication memory budget exhausted at stage={stage}, even with one record: {error}"
                ) from error
            midpoint = len(batch) // 2
            logger.warning(
                "Graph capture %s stage=%s memory limit; splitting %s records", capture_id, stage, len(batch)
            )
            commit(batch[:midpoint])
            commit(batch[midpoint:])
            return
        logger.info(
            "Graph capture %s stage=%s committed records=%s payload_bytes=%s seconds=%.3f",
            capture_id,
            stage,
            len(batch),
            len(json.dumps(batch).encode()),
            time.monotonic() - started,
        )

    for batch in payload_batches(records):
        commit(batch)


class GraphPublisher:
    def __init__(self, store):
        self.store = store

    def begin(self, session, capture, digest):
        @unit_of_work(timeout=graph_timeouts().control)
        def begin(tx):
            row = tx.run(
                "MERGE (c:GraphCapture {id:$id}) ON CREATE SET c.url=$url,c.host=$host "
                "SET c.publication_lock=coalesce(c.publication_lock,0)+1 "
                "WITH c OPTIONAL MATCH (active:GraphPublication {id:c.active_publication_id}) "
                "RETURN properties(c) AS capture, active.digest AS digest",
                id=capture["id"],
                url=capture.get("url"),
                host=capture.get("host"),
            ).single()
            current = row["capture"]
            if row["digest"] == digest:
                return current["active_publication_id"], True
            expected = current.get("active_publication_id", "")
            generation = identity("publication", capture["id"], digest, expected)
            previous_stage = current.get("staging_publication_id")
            if previous_stage and previous_stage != generation:
                tx.run(
                    "MATCH (p:GraphPublication {id:$id}) WHERE p.published_at IS NULL "
                    "SET p:GraphCleanupPending, p.state='abandoned', p.retired_at=timestamp()/1000.0",
                    id=previous_stage,
                ).consume()
            tx.run(
                "MERGE (p:GraphPublication {id:$publication.id}) "
                "ON CREATE SET p += $publication, p.created_at=timestamp()/1000.0 "
                "REMOVE p:GraphCleanupPending SET p.state='staging', p.retired_at=null, p.cleaned=false "
                "WITH p MATCH (c:GraphCapture {id:p.capture_id}) SET c.staging_publication_id=p.id",
                publication={
                    **capture,
                    "id": generation,
                    "capture_id": capture["id"],
                    "digest": digest,
                    "expected_active": expected,
                },
            ).consume()
            # Preserve compact context metadata for legacy evidence before the capture pointer changes.
            if current.get("complete") and not expected:
                tx.run(
                    "MERGE (p:GraphPublication {id:$id}) ON CREATE SET p += $metadata, p.state='legacy'",
                    id=identity("legacy-publication", capture["id"]),
                    metadata={
                        **current,
                        "id": identity("legacy-publication", capture["id"]),
                        "capture_id": capture["id"],
                        "published_at": current.get("published_at", 0),
                    },
                ).consume()
            if current.get("complete") and not expected:
                write_contexts(tx, context_records(
                    identity("legacy-publication", capture["id"]), "GraphPublication", current.get("context_urls", [])
                ))
            return generation, False

        return session.execute_write(begin)

    def activate(self, session, capture, generation):
        @unit_of_work(timeout=graph_timeouts().control)
        def activate(tx):
            row = tx.run(
                "MATCH (c:GraphCapture {id:$capture.id}) "
                "SET c.publication_lock=coalesce(c.publication_lock,0)+1 "
                "WITH c MATCH (p:GraphPublication {id:$generation}) "
                "WHERE p.state='staging' AND c.staging_publication_id=p.id "
                "AND coalesce(c.active_publication_id,'')=p.expected_active "
                "MERGE (revision:GraphState {id:'publication_revision'}) "
                "SET revision.value=coalesce(revision.value,0)+1 "
                "WITH c,p,revision.value AS revision, coalesce(c.active_publication_id,$legacy) AS previous "
                "SET c += $capture, c.complete=true, c.active_publication_id=p.id, "
                "c.staging_publication_id=null, c.published_at=timestamp()/1000.0, "
                "p.state='published', p.published_at=c.published_at, p.published_revision=revision "
                "WITH previous,p,revision OPTIONAL MATCH (old:GraphPublication {id:previous}) "
                "FOREACH (retired IN CASE WHEN old IS NULL THEN [] ELSE [old] END | "
                "SET retired:GraphCleanupPending, retired.state='retired', retired.retired_at=timestamp()/1000.0, "
                "retired.retired_revision=revision) "
                "RETURN p.id AS id",
                capture=capture,
                generation=generation,
                legacy=identity("legacy-publication", capture["id"]),
            ).single()
            if row is None:
                raise PublicationConflict("A newer capture generation was activated during publication")

        session.execute_write(activate)

    def abandon(self, session, generation):
        session.run(
            Query(
                "MATCH (p:GraphPublication {id:$id}), (c:GraphCapture {id:p.capture_id}) "
                "WHERE p.published_at IS NULL SET p:GraphCleanupPending, p.state='abandoned', "
                "p.retired_at=timestamp()/1000.0 "
                "WITH p,c WHERE c.staging_publication_id=p.id SET c.staging_publication_id=null",
                timeout=graph_timeouts().control,
            ),
            id=generation,
        ).consume()

    def publish(self, projection):
        started = time.monotonic()
        event = projection.event
        capture = {
            "id": event["id"],
            "url": projection.url,
            "observed_at": event["observed_at"],
            "timestamp_inferred": event["timestamp_inferred"],
            "backfill": event["backfill"],
            "resource_key": f"{event['data']['method'].upper()} {projection.url}",
            "host": urlsplit(projection.url).hostname,
            "context_capture_ids": [context["id"] for context in projection.contexts],
            "context_urls": list(dict.fromkeys(context["url"] for context in projection.contexts)),
            "gaps": projection.gaps,
            "analysis_version": ANALYZER_VERSION,
            "library_analysis": library_analysis(event.get("library_analysis")),
            "analysis_details": json.dumps(projection.analysis, sort_keys=True),
        }
        # Validate the small activation payload before creating any staging records.
        list(payload_batches([capture]))
        links = projection.planned_links
        if links is None:
            links = LinkPlanner(self.store, projection).plan()
        capture.update(
            entity_estimate=len(projection.nodes),
            relationship_estimate=len(set(projection.edges) | {link["id"] for link in links.values()}),
            summarized=any(item.get("mode") == "summary" for item in projection.analysis),
            budget_limited=any("budget reached" in gap.lower() for gap in projection.gaps)
            or any(item.get("budget_limited", False) for item in projection.analysis),
        )
        list(payload_batches([capture]))
        snapshot = projection_snapshot(projection)
        digest = identity("analysis", capture, snapshot["nodes"], snapshot["evidence"],
                          projection.edges, snapshot["_context_lists"], links)
        with self.store.connect().session(database="neo4j") as session:
            try:
                generation, completed = self.begin(session, capture, digest)
            except Neo4jError as error:
                if not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                    raise
                raise PublicationMemoryError(
                    f"Graph publication metadata exceeds the transaction memory budget: {error}"
                ) from error
            if not completed:
                try:
                    self.stage(session, capture, generation, projection, links)
                    self.validate_dependencies(links)
                    try:
                        self.activate(session, capture, generation)
                    except Neo4jError as error:
                        if not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                            raise
                        raise PublicationMemoryError(
                            f"Graph publication activation exceeds the transaction memory budget: {error}"
                        ) from error
                except (PublicationMemoryError, PublicationConflict):
                    try:
                        self.abandon(session, generation)
                    except Exception:
                        logger.warning(
                            "Graph staging retirement deferred for publication %s", generation, exc_info=True
                        )
                    raise
        logger.info("Graph capture %s publication activated seconds=%.3f", capture["id"], time.monotonic() - started)

    def validate_dependencies(self, links):
        ids = sorted(
            {
                link[f"_{side}_storage_id"]
                for link in links.values()
                for side in ("source", "target")
                if not link[f"_{side}_local"]
            }
        )
        for batch in batched(ids, WRITE_BATCH_SIZE):
            rows = self.store.read(
                f"UNWIND $ids AS id MATCH (n:GraphEntity {{id:id}}) WHERE {visible_node('n')} RETURN n.id AS id",
                ids=list(batch),
            )
            if {row["id"] for row in rows} != set(batch):
                raise PublicationConflict("An inferred link dependency changed during publication; replan the capture")

    def stage(self, session, capture, generation, projection, links):
        write_batches(
            session, capture["id"], "context-lookup",
            "UNWIND $rows AS row MERGE (n:GraphContext {id:row.id}) SET n += row", "rows",
            context_records(generation, "GraphPublication", capture.get("context_urls", [])),
        )
        def stored(record):
            result = {
                **record,
                "id": identity(generation, record["id"]),
                "_logical_id": record["id"],
                "_publication_id": generation,
                "_owner_capture_id": capture["id"],
            }
            if record.get("context_urls"):
                result.update(context_urls=None, context_owner_id=generation)
            return result

        def edges():
            for edge in projection.edges.values():
                yield {
                    **stored(edge),
                    "_build_capture_id": capture["id"],
                    "_source_storage_id": identity(generation, edge["source"]),
                    "_target_storage_id": identity(generation, edge["target"]),
                    "evidence_id": identity(generation, edge["evidence_id"]),
                }
            for link in links.values():
                record = {
                    key: value
                    for key, value in link.items()
                    if key not in {"_source_local", "_target_local", "_proof_local"}
                }
                record.update(
                    id=identity(generation, link["id"]),
                    _logical_id=link["id"],
                    _publication_id=generation,
                    _build_capture_id=capture["id"],
                )
                if link["_source_local"]:
                    record["_source_storage_id"] = identity(generation, link["_source_storage_id"])
                if link["_target_local"]:
                    record["_target_storage_id"] = identity(generation, link["_target_storage_id"])
                if link["_proof_local"]:
                    record["evidence_id"] = identity(generation, link["evidence_id"])
                yield record

        write_batches(
            session,
            capture["id"],
            "entities",
            "UNWIND $nodes AS n MERGE (e:GraphEntity {id:n.id}) SET e += n",
            "nodes",
            ({**stored(node), "_reverse_host": reverse_host(node["url"])} for node in projection.nodes.values()),
        )
        write_batches(
            session,
            capture["id"],
            "evidence",
            "UNWIND $evidence AS n MERGE (e:GraphEvidence {id:n.id}) ON CREATE SET e += n "
            "WITH e MATCH (c:GraphCapture {id:e.capture_id}), (p:GraphPublication {id:e._publication_id}) "
            "MERGE (e)-[:FROM_CAPTURE]->(c) MERGE (e)-[:FROM_PUBLICATION]->(p)",
            "evidence",
            (stored(evidence) for evidence in projection.evidence.values()),
        )
        write_batches(
            session,
            capture["id"],
            "relationships",
            "UNWIND $edges AS r MATCH (a:GraphEntity {id:r._source_storage_id}), "
            "(b:GraphEntity {id:r._target_storage_id}) MERGE (a)-[e:RELATES {id:r.id}]->(b) SET e += r",
            "edges",
            edges(),
        )
        after = ""
        while True:
            rows = self.store.read(
                "MATCH (e:GraphEvidence {capture_id:$capture}) WHERE e._publication_id IS NULL AND e.id>$after "
                "RETURN e.id AS id ORDER BY e.id LIMIT $limit",
                capture=capture["id"],
                after=after,
                limit=WRITE_BATCH_SIZE,
            )
            if not rows:
                break
            write_batches(
                session,
                capture["id"],
                "legacy-evidence",
                "UNWIND $rows AS row MATCH (e:GraphEvidence {id:row.id}) SET e.context_owner_id=row.owner",
                "rows",
                ({**row, "owner": identity("legacy-publication", capture["id"])} for row in rows),
            )
            after = rows[-1]["id"]
        after = ""
        while True:
            rows = self.store.read(
                "MATCH (n:GraphEntity {context_owner_id:$capture}) WHERE n._publication_id IS NULL AND n.id>$after "
                "RETURN n.id AS id ORDER BY n.id LIMIT $limit",
                capture=capture["id"],
                after=after,
                limit=WRITE_BATCH_SIZE,
            )
            if not rows:
                break
            write_batches(
                session,
                capture["id"],
                "legacy-context",
                "UNWIND $rows AS row MATCH (n:GraphEntity {id:row.id}) SET n.context_owner_id=row.owner",
                "rows",
                ({**row, "owner": identity("legacy-publication", capture["id"])} for row in rows),
            )
            after = rows[-1]["id"]

    def cleanup(self, *, deadline=None, stop_event=None):
        """Reclaim only pending generations within a cooperative maintenance budget."""
        started = time.monotonic()
        deadline = started + 60 if deadline is None else deadline
        summary = {"selected": 0, "completed": 0, "deleted": 0}

        def available():
            return time.monotonic() < deadline and not (stop_event and stop_event.is_set())

        def read(statement, **parameters):
            return self.store.read(statement, timeout=deadline - time.monotonic(), **parameters)

        if not available():
            return summary
        publications = read(
            "MATCH (p:GraphPublication:GraphCleanupPending) "
            "USING INDEX p:GraphCleanupPending(retired_at,id) "
            "WHERE p.retired_at<$cutoff AND p.id IS NOT NULL "
            "AND p.state IN ['retired','abandoned'] AND coalesce(p.cleaned,false)=false "
            "RETURN p.id AS id, p.capture_id AS capture, p.published_at IS NULL AS abandoned "
            "ORDER BY p.retired_at,p.id LIMIT 5",
            cutoff=time.time() - CLEANUP_GRACE_SECONDS,
        )
        summary["selected"] = len(publications)
        remaining = CLEANUP_BATCHES
        with self.store.connect().session(database="neo4j") as session:
            for publication in publications:
                for select, delete in self.cleanup_stages(publication):
                    while remaining and available():
                        rows = read(
                            select, id=publication["id"], capture=publication["capture"],
                            limit=WRITE_BATCH_SIZE, cutoff=time.time() - CLEANUP_GRACE_SECONDS,
                        )
                        if not rows:
                            break
                        if not available():
                            return summary
                        write_batches(
                            session, publication["capture"], "cleanup", delete, "rows",
                            ({**row, "publication": publication["id"],
                              "cutoff": time.time() - CLEANUP_GRACE_SECONDS} for row in rows),
                            deadline=min(deadline, time.monotonic() + graph_timeouts().read),
                        )
                        summary["deleted"] += len(rows)
                        remaining -= 1
                    if not remaining or not available():
                        return summary
                if not available():
                    return summary
                statement = (
                    "UNWIND $rows AS row MATCH (p:GraphPublication {id:row.publication}) "
                    "SET p.cleanup_lock=coalesce(p.cleanup_lock,0)+1 WITH p "
                    "MATCH (c:GraphCapture {id:p.capture_id}) "
                    "WHERE p.state IN ['retired','abandoned'] "
                    "AND coalesce(c.active_publication_id,'')<>p.id "
                    "AND coalesce(c.staging_publication_id,'')<>p.id "
                    "SET p.cleaned=true REMOVE p:GraphCleanupPending"
                )
                write_batches(
                    session, publication["capture"], "cleanup-complete", statement, "rows",
                    [{"publication": publication["id"]}],
                    deadline=min(deadline, time.monotonic() + graph_timeouts().read),
                )
                summary["completed"] += 1
        return summary

    @staticmethod
    def cleanup_stages(publication):
        legacy = publication["id"] == identity("legacy-publication", publication["capture"])
        owner = "n.capture_id=$capture AND n._publication_id IS NULL" if legacy else "n._publication_id=$id"
        relation = "r.capture_id=$capture AND r._publication_id IS NULL" if legacy else "r._publication_id=$id"
        stages = [
            (
                f"MATCH ()-[r:RELATES]->() WHERE {relation} RETURN r.id AS id ORDER BY r.id LIMIT $limit",
                "UNWIND $rows AS row MATCH ()-[r:RELATES {id:row.id}]->() DELETE r",
            ),
            (
                f"MATCH (n:GraphEntity)-[r:RELATES]-() WHERE {owner} "
                "RETURN DISTINCT r.id AS id ORDER BY id LIMIT $limit",
                "UNWIND $rows AS row MATCH ()-[r:RELATES {id:row.id}]->() DELETE r",
            ),
            (
                f"MATCH (n:GraphEntity) WHERE {owner} AND NOT EXISTS {{ MATCH (n)--() }} "
                "RETURN n.id AS id ORDER BY n.id LIMIT $limit",
                "UNWIND $rows AS row MATCH (n:GraphEntity {id:row.id}) WHERE NOT EXISTS { MATCH (n)--() } "
                "OPTIONAL MATCH (lookup:GraphContext {owner_id:n.id,owner_kind:'GraphEntity'}) DELETE lookup,n",
            ),
        ]
        stages.append((
            "MATCH (n:GraphContext {owner_id:$id}) RETURN n.id AS id ORDER BY n.id LIMIT $limit",
            "UNWIND $rows AS row MATCH (n:GraphContext {id:row.id}) DELETE n",
        ))
        if publication["abandoned"]:
            stages.append(
                (
                    "MATCH (e:GraphEvidence {_publication_id:$id}) RETURN e.id AS id ORDER BY e.id LIMIT $limit",
                    "UNWIND $rows AS row MATCH (e:GraphEvidence {id:row.id}) DETACH DELETE e",
                )
            )
        select_guard = (
            "MATCH (p:GraphPublication {id:$id}), (c:GraphCapture {id:p.capture_id}) "
            "WHERE p.state IN ['retired','abandoned'] AND p.retired_at<$cutoff "
            "AND coalesce(c.active_publication_id,'')<>p.id "
            "AND coalesce(c.staging_publication_id,'')<>p.id WITH p,c "
        )
        delete_guard = (
            "UNWIND $rows AS row MATCH (p:GraphPublication {id:row.publication}) "
            "SET p.cleanup_lock=coalesce(p.cleanup_lock,0)+1 WITH row,p "
            "MATCH (c:GraphCapture {id:p.capture_id}) "
            "WHERE p.state IN ['retired','abandoned'] AND p.retired_at<row.cutoff "
            "AND coalesce(c.active_publication_id,'')<>p.id "
            "AND coalesce(c.staging_publication_id,'')<>p.id WITH row,p,c "
        )
        return [
            (select_guard + select, delete.replace("UNWIND $rows AS row ", delete_guard)) for select, delete in stages
        ]
