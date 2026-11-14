"""Small durable status obligations for materialized analysis units."""

import json

from neo4j import unit_of_work

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.model import identity


def enqueue(connection, unit, generation, materialization, error="", flow=None, discovery=None):
    if not generation:
        return
    row = connection.execute(
        "SELECT metadata FROM graph_inventory_generations WHERE id=? AND unit_id=?", (generation, unit)
    ).fetchone()
    if row is None:
        raise ValueError("Inventory generation metadata is unavailable")
    original = json.loads(row[0])
    metadata = json.dumps({"discovery": discovery or original["discovery"], "flow": flow or original["flow"],
                           "materialization": materialization, "error": error[:1000]}, sort_keys=True)
    connection.execute(
        "INSERT INTO graph_inventory_updates VALUES (?,?,1,0,?) "
        "ON CONFLICT(unit_id,generation) DO UPDATE SET version=version+1,metadata=excluded.metadata",
        (unit, generation, metadata),
    )


def deliver(session, connection, row):
    unit, generation, version, metadata = row
    key = identity("inventory-status", unit, generation, version, metadata)

    @unit_of_work(timeout=graph_timeouts().control)
    def publish(tx):
        tx.run(
            "MATCH (s:GraphState {id:'publication_revision'}) SET s.status_lock=coalesce(s.status_lock,0)+1"
        ).consume()
        found = tx.run("MATCH (s:GraphInventoryStatus {id:$id}) RETURN s.id AS id", id=key).single()
        if found:
            return
        revision = tx.run(
            "MATCH (s:GraphState {id:'publication_revision'}) SET s.value=s.value+1 RETURN s.value AS revision"
        ).single()["revision"]
        values = {**json.loads(metadata), "id": key, "unit_id": unit, "generation": generation,
                  "published_revision": revision}
        tx.run("CREATE (s:GraphInventoryStatus) SET s += $values", values=values).consume()

    session.execute_write(publish)
    connection.execute(
        "UPDATE graph_inventory_updates SET delivered=max(delivered,?) WHERE unit_id=? AND generation=?",
        (version, unit, generation),
    )
