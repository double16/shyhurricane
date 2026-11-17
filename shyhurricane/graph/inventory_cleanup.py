"""Retire inventory generations without deleting reader-pinned data or unconfirmed files."""

import logging
import sqlite3
import time
from contextlib import closing

from neo4j import Query, unit_of_work

from shyhurricane.graph.performance import count, measured

logger = logging.getLogger(__name__)

ELIGIBLE = (
    "g.state IN ['retired','abandoned'] AND g.retired_at<$before "
    "AND NOT EXISTS { MATCH (u:GraphInventoryUnit {id:g.unit_id}) WHERE u.active=g.id OR u.staging=g.id } "
    "AND NOT EXISTS { MATCH (p:GraphInventoryReadPin) WHERE p.expires>$now "
    "AND g.published_revision<=p.revision "
    "AND (g.retired_revision IS NULL OR p.revision<g.retired_revision) }"
)


class InventoryCleanup:
    def __init__(self, store, database):
        self.store = store
        self.database = database
        self.after = ""
        self.candidate_after = ""

    @measured("inventory_cleanup", logger, quiet=True)
    def step(self, *, deadline=None):
        if not self.database.exists():
            return False
        if deadline is not None and time.monotonic() >= deadline:
            return False
        deadline = min(deadline or float("inf"), time.monotonic() + 2)
        with self.store.connect().session(database="neo4j") as session:
            def remaining():
                return max(0.001, deadline - time.monotonic())
            session.run(Query(
                "MATCH (p:GraphInventoryReadPin) WHERE p.expires<=$now "
                "WITH p LIMIT 500 DELETE p", timeout=remaining(),
            ), now=time.time()).consume()
            candidates = list(session.run(Query(
                "MATCH (g:GraphInventoryGeneration) "
                "USING INDEX g:GraphInventoryGeneration(state,id) "
                "WHERE g.state='cleaning' AND g.id>$after RETURN g.id AS id ORDER BY g.id LIMIT 100",
                timeout=remaining(),
            ), after=self.candidate_after))
            if not candidates:
                candidates = list(session.run(Query(
                    "MATCH (g:GraphInventoryGeneration) "
                    "USING INDEX g:GraphInventoryGeneration(state,retired_at,id) "
                    "WHERE g.state IN ['retired','abandoned'] AND g.retired_at<$before "
                    "AND g.id>$after RETURN g.id AS id ORDER BY g.id LIMIT 100",
                    timeout=remaining(),
                ), before=time.time() - 300, after=self.candidate_after))
            self.candidate_after = candidates[-1]["id"] if len(candidates) == 100 else ""
            count("candidates", len(candidates))
            generation = None
            for candidate in candidates:
                if time.monotonic() >= deadline:
                    return True
                # Explicit transactions avoid managed retries extending the pass budget.
                with session.begin_transaction(timeout=min(0.25, remaining())) as tx:
                    tx.run(
                        "MATCH (s:GraphState {id:'publication_revision'}) "
                        "SET s.pin_lock=coalesce(s.pin_lock,0)+1"
                    ).consume()
                    row = tx.run(
                        "MATCH (g:GraphInventoryGeneration {id:$id}) "
                        "WHERE g.state='cleaning' OR (" + ELIGIBLE + ") "
                        "SET g.state='cleaning' RETURN g.id AS id",
                        id=candidate["id"], now=time.time(), before=time.time() - 300,
                    ).single()
                    tx.commit()
                if row:
                    generation = row["id"]
                    break
            if generation is not None:
                for label in ("relationships", "GraphInventoryFact", "GraphInventoryScope", "GraphInventoryMembership", "GraphInventoryContext", "GraphInventoryStatus", "GraphInventoryBatch"):
                    if deadline is not None and time.monotonic() >= deadline:
                        return True

                    @unit_of_work(timeout=remaining())
                    def remove(tx):
                        if label == "relationships":
                            return tx.run(
                                "MATCH (f:GraphInventoryFact {generation:$generation})-[r]-() "
                                "WITH DISTINCT r LIMIT 500 DELETE r RETURN count(*) AS count",
                                generation=generation,
                            ).single()["count"]
                        return tx.run(
                            f"MATCH (n:{label} {{generation:$generation}}) WHERE NOT EXISTS {{ MATCH (n)--() }} "
                            "WITH n LIMIT 500 DELETE n RETURN count(*) AS count", generation=generation,
                        ).single()["count"]
                    with session.begin_transaction(timeout=remaining()) as tx:
                        deleted = remove(tx)
                        tx.commit()
                    count("deleted_records", deleted)
                    if deleted:
                        return True
                session.run(Query(
                    "MATCH (g:GraphInventoryGeneration {id:$generation}) WHERE g.state='cleaning' "
                    "SET g.state='cleaned',g.cleaned_at=timestamp()/1000.0", timeout=remaining()),
                    generation=generation,
                ).consume()
            # A remote tombstone must exist before local obligations/artifact pins are released.
            with closing(sqlite3.connect(self.database, timeout=0.05)) as connection:
                rows = connection.execute(
                    "SELECT id FROM graph_inventory_generations WHERE state IN ('active','abandoned','failed') AND id>? "
                    "ORDER BY id LIMIT 100", (self.after,),
                ).fetchall()
                self.after = rows[-1][0] if len(rows) == 100 else ""
                if not rows:
                    return generation is not None
                cleaned = list(session.run(Query(
                    "MATCH (g:GraphInventoryGeneration) WHERE g.id IN $ids AND g.state='cleaned' RETURN g.id AS id", timeout=remaining()),
                    ids=[row[0] for row in rows],
                ))
                with connection:
                    for row in cleaned:
                        connection.execute("DELETE FROM graph_inventory_outbox WHERE generation=?", (row["id"],))
                        connection.execute(
                            "UPDATE graph_inventory_generations SET state='cleaned',artifact=NULL WHERE id=?", (row["id"],)
                        )
        return generation is not None or bool(cleaned)
