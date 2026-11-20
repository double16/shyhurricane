"""Drain durable inventory obligations independently from parser subprocess lifetimes."""

import json
import logging
import time

from neo4j import unit_of_work

from shyhurricane.graph.config import graph_timeouts

from shyhurricane.graph.retry_policy import transient_neo4j_error

logger = logging.getLogger(__name__)

from shyhurricane.graph.inventory_publication import InventoryPublisher, initialize
from shyhurricane.graph.inventory_scope import url_properties
from shyhurricane.graph.model import identity
from shyhurricane.graph.performance import commit_timing, count, label, measured, phase, timed


class InventoryPipeline:
    def __init__(self, artifacts, store):
        self.artifacts = artifacts
        self.connection = artifacts.connection
        self.store = store
        self.ready = False
        self.current = None
        self.staged = None
        self.next_attempt = 0
        self.retries = 0

    def available(self):
        if time.monotonic() < self.next_attempt:
            return False
        return any(self.connection.execute(sql).fetchone() is not None for sql in (
            "SELECT 1 FROM graph_inventory_updates WHERE version>delivered LIMIT 1",
            "SELECT 1 FROM graph_inventory_generations WHERE state='pending' LIMIT 1",
            "SELECT 1 FROM captures WHERE seq>(SELECT after_seq FROM graph_inventory_catalog WHERE id=1) LIMIT 1",
        ))

    @timed("initialization")
    def initialize(self, session):
        if self.ready:
            return
        initialize(session)
        dataset = self.connection.execute("SELECT id FROM graph_dataset").fetchone()[0]
        claimed = session.execute_write(lambda tx: tx.run(
            "MERGE (s:GraphState {id:'inventory_dataset'}) ON CREATE SET s.value=$id "
            "RETURN s.value AS id", id=dataset,
        ).single()["id"])
        if claimed != dataset:
            raise ValueError("Graph and artifact stores belong to different assessments")
        self.ready = True

    def step(self):
        if time.monotonic() < self.next_attempt:
            return True
        self.current = None
        try:
            result = self._step()
            self.retries = 0
            return result
        except Exception as error:
            if transient_neo4j_error(error):
                self.retries += 1
                self.next_attempt = time.monotonic() + min(300, 2 ** min(self.retries, 8))
                logger.warning("Inventory publication retry type=%s retries=%s next_attempt_seconds=%.3f",
                               type(error).__name__, self.retries,
                               max(0, self.next_attempt - time.monotonic()), exc_info=True)
                return True
            if self.current is None:
                raise
            with commit_timing(self.connection):
                self.connection.execute(
                    "UPDATE graph_inventory_generations SET state='failed',error=? WHERE id=?",
                    (f"{type(error).__name__}: {error}"[:1000], self.current),
                )
                from shyhurricane.graph.inventory_updates import enqueue

                unit = self.connection.execute(
                    "SELECT unit_id FROM graph_inventory_generations WHERE id=?", (self.current,)
                ).fetchone()[0]
                enqueue(self.connection, unit, self.current, "failed", str(error), flow="failed", discovery="failed")
            logger.error("Inventory generation failed id=%s", self.current, exc_info=True)
            return True

    @measured("inventory_publish", logger, quiet=True)
    def _step(self):
        update = self.connection.execute(
            "SELECT unit_id,generation,version,metadata FROM graph_inventory_updates WHERE version>delivered LIMIT 1"
        ).fetchone()
        if update:
            label(stage="status", unit_id=update[0], generation_id=update[1])
            count("records")
            from shyhurricane.graph.inventory_updates import deliver

            with self.store.connect().session(database="neo4j") as session:
                self.initialize(session)
                with commit_timing(self.connection):
                    with phase("status_write"):
                        deliver(session, self.connection, update)
            return True
        after = self.connection.execute("SELECT after_seq FROM graph_inventory_catalog WHERE id=1").fetchone()[0]
        captures = self.connection.execute(
            "SELECT c.seq,c.id,c.url,c.stamp,m.method FROM main.captures c "
            "JOIN graph_capture_metadata m ON m.capture_id=c.id WHERE c.seq>? ORDER BY c.seq LIMIT 500", (after,),
        ).fetchall()
        if captures:
            label(stage="catalog")
            count("records", len(captures))
            with self.store.connect().session(database="neo4j") as session:
                self.initialize(session)
                publisher = InventoryPublisher(session)
                with phase("catalog_write"):
                    publisher.register_captures([
                        {"id": row[1], "url": row[2], "observed_at": row[3], "method": row[4]} for row in captures
                    ])
            with commit_timing(self.connection):
                self.connection.execute("UPDATE graph_inventory_catalog SET after_seq=? WHERE id=1",
                                        (captures[-1][0],))
            return True
        row = self.connection.execute(
            "SELECT id,unit_id,capture_id,metadata FROM graph_inventory_generations "
            "WHERE state='pending' ORDER BY epoch,rowid LIMIT 1"
        ).fetchone()
        if row is None:
            return False
        generation, unit, capture_id, encoded = row
        self.current = generation
        label(stage="generation", generation_id=generation, unit_id=unit, capture_id=capture_id)
        metadata = json.loads(encoded)
        with self.store.connect().session(database="neo4j") as session:
            self.initialize(session)
            publisher = InventoryPublisher(session)
            if self.staged != generation:
                with phase("generation_reservation"):
                    previous = session.run(
                        "MATCH (u:GraphInventoryUnit {id:$unit}) RETURN u.staging AS staging", unit=unit,
                    ).single()
                    if previous and previous["staging"] not in (None, generation):
                        old = previous["staging"]
                        state = self.connection.execute(
                            "SELECT state FROM graph_inventory_generations WHERE id=?", (old,),
                        ).fetchone()
                        if state and state[0] in {"waiting", "failed"}:
                            @unit_of_work(timeout=graph_timeouts().control)
                            def abandon(tx):
                                tx.run(
                                    "MATCH (u:GraphInventoryUnit {id:$unit}) "
                                    "SET u.lock=coalesce(u.lock,0)+1", unit=unit,
                                ).consume()
                                return tx.run(
                                    "MATCH (u:GraphInventoryUnit {id:$unit}),(g:GraphInventoryGeneration {id:$old}) "
                                    "WHERE u.staging=$old AND g.state='staging' "
                                    "SET u.staging=null,g.state='abandoned',g.retired_at=timestamp()/1000.0",
                                    unit=unit, old=old,
                                ).consume()

                            session.execute_write(abandon)
                            with commit_timing(self.connection):
                                self.connection.execute(
                                    "UPDATE graph_inventory_generations SET state='abandoned' WHERE id=?", (old,)
                                )
                    publisher.register_capture({"id": capture_id, "url": metadata["url"],
                                                "method": metadata["method"], "observed_at": metadata["observed_at"]})
                    publisher.begin(unit, generation, {"id": capture_id, **metadata})
                    self.staged = generation
            obligation = self.connection.execute(
                "SELECT id,generation,sequence,shard,metadata FROM graph_inventory_outbox "
                "WHERE generation=? AND state='pending' ORDER BY sequence LIMIT 1", (generation,),
            ).fetchone()
            if obligation:
                label(stage="facts", batch_id=obligation[0], sequence=obligation[2], shard_id=obligation[3])
                with commit_timing(self.connection):
                    self.artifacts.manifest.outbox.deliver(session, obligation)
                return True
            if metadata["discovery"] == "pending" and not metadata.get("sealed"):
                label(stage="waiting")
                # Do not let an unfinished unit starve other completed generations.
                with commit_timing(self.connection):
                    self.connection.execute(
                        "UPDATE graph_inventory_generations SET state='waiting' WHERE id=?", (generation,)
                    )
                return True
            after = self.connection.execute(
                "SELECT context_after FROM graph_inventory_generations WHERE id=?", (generation,),
            ).fetchone()[0]
            contexts = self.connection.execute(
                "SELECT rowid,context_id,url FROM graph_unit_contexts WHERE unit_id IN "
                "(SELECT ? UNION SELECT parent_id FROM graph_unit_parents WHERE unit_id=?) "
                "AND rowid>? ORDER BY rowid LIMIT 500", (unit, unit, after),
            ).fetchall()
            if contexts:
                label(stage="contexts")
                count("records", len(contexts))
                records = [{"id": identity("inventory-context", generation, context), "capture_id": context,
                            "generation": generation, "url": url, **url_properties(url)}
                           for _, context, url in contexts]
                with phase("contexts_write"):
                    session.execute_write(lambda tx: tx.run(
                        "UNWIND $rows AS row MERGE (c:GraphInventoryContext {id:row.id}) "
                        "ON CREATE SET c += row", rows=records,
                    ).consume())
                with commit_timing(self.connection):
                    self.connection.execute(
                        "UPDATE graph_inventory_generations SET context_after=? WHERE id=?",
                        (contexts[-1][0], generation),
                    )
                return True
            label(stage="activation")
            with phase("fact_count"):
                facts = session.run(
                    "MATCH (f:GraphInventoryFact {generation:$generation}) RETURN count(f) AS count",
                    generation=generation,
                ).single()["count"]
            count("facts", facts)
            batches = self.connection.execute(
                "SELECT count(*) FROM graph_inventory_outbox WHERE generation=?", (generation,)
            ).fetchone()[0]
            with phase("generation_metadata"):
                session.execute_write(lambda tx: tx.run(
                    "MATCH (g:GraphInventoryGeneration {id:$generation}) "
                    "SET g.artifact=$artifact,g.error=$error,g.materialization=$materialization,g.source_path=$source_path",
                    generation=generation, artifact=metadata["artifact"], error=metadata["error"],
                    materialization=metadata["materialization"], source_path=metadata["source_path"],
                ).consume())
            with phase("activation"):
                publisher.activate(unit, generation, batches=batches, facts=facts,
                                   discovery=metadata["discovery"], flow=metadata["flow"])
            with commit_timing(self.connection):
                self.connection.execute(
                    "UPDATE graph_inventory_generations SET state='active' WHERE id=?", (generation,)
                )
        return True
