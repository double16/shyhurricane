"""Requires a dedicated fresh Neo4j, separate from application and other graph tests."""

import json
import os
import sqlite3
import time
from uuid import uuid4

import pytest
from neo4j import GraphDatabase

from shyhurricane.graph.inventory_outbox import InventoryOutbox
from shyhurricane.graph.inventory_outbox import initialize as initialize_outbox
from shyhurricane.graph.inventory_publication import (
    InventoryIncomplete,
    InventoryPublisher,
    initialize,
    visible_inventory,
)
from shyhurricane.graph.shard_store import ShardStore

pytestmark = pytest.mark.skipif(not os.environ.get("GRAPH_INVENTORY_TEST_URI"),
                                reason="Requires a dedicated fresh inventory test Neo4j")


def test_remote_commit_recovery_and_atomic_visibility(tmp_path, inventory_database):
    driver = GraphDatabase.driver(os.environ["GRAPH_INVENTORY_TEST_URI"], auth=None)
    connection = sqlite3.connect(tmp_path / "outbox.sqlite")
    shards = ShardStore(tmp_path, connection)
    initialize_outbox(connection)
    outbox = InventoryOutbox(connection, shards)
    prefix = uuid4().hex
    unit, generation, replacement = (prefix + name for name in ("unit", "generation", "replacement"))
    records = [{"id": str(i), "manifest_id": str(i), "capture_id": prefix + "capture",
                "analysis_unit_id": unit, "kind": "symbol", "url": "https://example.com/app.js"}
               for i in range(501)]
    try:
        with driver.session() as session:
            initialize(session)
            publisher = InventoryPublisher(session)
            capture = {"id": prefix + "capture", "url": "https://example.com/app.js",
                       "observed_at": 1, "method": "GET"}
            before = session.run(
                "MATCH (s:GraphState {id:'publication_revision'}) RETURN s.value AS revision"
            ).single()["revision"]
            assert publisher.begin(unit, generation, capture) == "staging"
            with connection:
                outbox.enqueue(generation, records)
            first = outbox.pending()[0]
            outbox.deliver(session, first)
            connection.rollback()
            assert outbox.pending()[0][0] == first[0]
            with pytest.raises(InventoryIncomplete):
                publisher.activate(unit, generation, batches=2, facts=501)
            assert session.run("MATCH (u:GraphInventoryUnit {id:$unit}) RETURN u.active AS active",
                               unit=unit).single()["active"] is None
            for obligation in outbox.pending(500):
                with connection:
                    outbox.deliver(session, obligation)
            revision = publisher.activate(unit, generation, batches=2, facts=501)
            assert revision == before + 1
            assert publisher.activate(unit, generation, batches=2, facts=501) == revision
            with connection:
                outbox.deliver(session, first)  # Replay is also valid after activation.
            assert session.run("MATCH (f:GraphInventoryFact {generation:$generation}) RETURN count(f) AS count",
                               generation=generation).single()["count"] == 501
            positions = list(session.run(
                "MATCH (f:GraphInventoryFact {generation:$generation}) "
                "RETURN f.manifest_id AS id,f.shard AS shard,f.position AS position",
                generation=generation,
            ))
            payloads = {row["id"]: shards.read(row["shard"])[row["position"]] for row in positions}
            assert payloads == {row["manifest_id"]: row for row in records}
            assert publisher.begin(unit, replacement, capture) == "staging"
            with connection:
                outbox.enqueue(replacement, records[:1])
            with connection:
                outbox.deliver(session, outbox.pending()[0])
            new_revision = publisher.activate(unit, replacement, batches=1, facts=1)
            assert new_revision == revision + 1
            for selected, expected in ((revision, generation), (new_revision, replacement)):
                rows = list(session.run(
                    "MATCH (g:GraphInventoryGeneration {unit_id:$unit}) WHERE " + visible_inventory()
                    + " RETURN g.id AS id", unit=unit, revision=selected,
                ))
                assert [row["id"] for row in rows] == [expected]
            pin = publisher.pin(prefix, revision, time.time() + 600)
            assert session.run("MATCH (p:GraphInventoryReadPin {id:$id}) RETURN p.revision AS revision",
                               id=pin).single()["revision"] == revision
            assert json.loads(first[4])[0]["reverse_host"] == "moc.elpmaxe."
    finally:
        connection.close()
        driver.close()
