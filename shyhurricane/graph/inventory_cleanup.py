"""Retire inventory generations without deleting reader-pinned data or unconfirmed files."""

import sqlite3
import time
from contextlib import closing

from neo4j import unit_of_work

from shyhurricane.graph.config import graph_timeouts

ELIGIBLE = (
    "g.state IN ['retired','abandoned'] AND g.retired_at<$before "
    "AND NOT EXISTS { MATCH (u:GraphInventoryUnit) WHERE u.active=g.id OR u.staging=g.id } "
    "AND NOT EXISTS { MATCH (p:GraphInventoryReadPin) WHERE p.expires>$now "
    "AND g.published_revision<=p.revision "
    "AND (g.retired_revision IS NULL OR p.revision<g.retired_revision) }"
)


class InventoryCleanup:
    def __init__(self, store, database):
        self.store = store
        self.database = database
        self.after = ""

    def step(self, *, deadline=None):
        if not self.database.exists():
            return False
        if deadline is not None and time.monotonic() >= deadline:
            return False
        with self.store.connect().session(database="neo4j") as session:
            @unit_of_work(timeout=graph_timeouts().control)
            def select(tx):
                tx.run(
                    "MATCH (s:GraphState {id:'publication_revision'}) "
                    "SET s.pin_lock=coalesce(s.pin_lock,0)+1"
                ).consume()
                tx.run(
                    "MATCH (p:GraphInventoryReadPin) WHERE p.expires<=$now WITH p LIMIT 500 DELETE p",
                    now=time.time(),
                ).consume()
                row = tx.run(
                    "MATCH (g:GraphInventoryGeneration) WHERE g.state='cleaning' OR (" + ELIGIBLE + ") "
                    "WITH g ORDER BY g.id LIMIT 1 SET g.state='cleaning' RETURN g.id AS id",
                    now=time.time(), before=time.time() - 300,
                ).single()
                return row["id"] if row else None
            generation = session.execute_write(select)
            if generation is not None:
                for label in ("relationships", "GraphInventoryFact", "GraphInventoryScope", "GraphInventoryMembership", "GraphInventoryContext", "GraphInventoryStatus", "GraphInventoryBatch"):
                    if deadline is not None and time.monotonic() >= deadline:
                        return True

                    @unit_of_work(timeout=graph_timeouts().write)
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
                    if session.execute_write(remove):
                        return True
                session.execute_write(lambda tx: tx.run(
                    "MATCH (g:GraphInventoryGeneration {id:$generation}) WHERE g.state='cleaning' "
                    "SET g.state='cleaned',g.cleaned_at=timestamp()/1000.0",
                    generation=generation,
                ).consume())
            # A remote tombstone must exist before local obligations/artifact pins are released.
            with closing(sqlite3.connect(self.database, timeout=0.05)) as connection:
                rows = connection.execute(
                    "SELECT id FROM graph_inventory_generations WHERE state IN ('active','abandoned') AND id>? "
                    "ORDER BY id LIMIT 100", (self.after,),
                ).fetchall()
                self.after = rows[-1][0] if len(rows) == 100 else ""
                if not rows:
                    return generation is not None
                cleaned = list(session.run(
                    "MATCH (g:GraphInventoryGeneration) WHERE g.id IN $ids AND g.state='cleaned' RETURN g.id AS id",
                    ids=[row[0] for row in rows],
                ))
                with connection:
                    for row in cleaned:
                        connection.execute("DELETE FROM graph_inventory_outbox WHERE generation=?", (row["id"],))
                        connection.execute(
                            "UPDATE graph_inventory_generations SET state='cleaned',artifact=NULL WHERE id=?", (row["id"],)
                        )
        return generation is not None or bool(cleaned)
