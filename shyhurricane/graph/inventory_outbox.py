"""Durable shard-level obligations; Neo4j receipts precede local acknowledgement."""

import json

from neo4j import unit_of_work

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.inventory_publication import InventoryConflict
from shyhurricane.graph.inventory_scope import url_properties
from shyhurricane.graph.model import identity
from shyhurricane.graph.payload_store import initialize as initialize_payloads
from shyhurricane.graph.performance import count, label, phase
from shyhurricane.graph.shard_store import SHARD_BYTES, batches, encode


def initialize(connection):
    initialize_payloads(connection)
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS graph_inventory_outbox("
        "id TEXT PRIMARY KEY,generation TEXT NOT NULL,sequence INTEGER NOT NULL,"
        "shard TEXT NOT NULL,metadata TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',"
        "UNIQUE(generation,sequence));"
        "CREATE INDEX IF NOT EXISTS graph_inventory_shard ON graph_inventory_outbox(shard);"
        "CREATE INDEX IF NOT EXISTS graph_inventory_pending ON graph_inventory_outbox(state,generation,sequence);"
    )


class InventoryOutbox:
    def __init__(self, connection, shards):
        self.connection = connection
        self.shards = shards

    def enqueue(self, generation, records, *, start=0):
        """Caller owns the SQL transaction and advances its archive cursor with these rows."""
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        result = []
        for sequence, batch in enumerate(batches(records), start):
            reference = self.shards.put(batch)
            metadata = []
            for position, record in enumerate(batch):
                url = record.get("url") or record.get("owner_url") or ""
                metadata.append({
                    "id": identity("inventory-storage-v4", generation, record["manifest_id"]),
                    "manifest_id": record["manifest_id"], "logical_id": record.get("id", ""),
                    "generation": generation, "capture_id": record["capture_id"],
                    "unit_id": record["analysis_unit_id"], "kind": record["kind"],
                    "url": url, "role": record.get("role", ""),
                    "method": record.get("method", "GET"), "shard": reference, "position": position,
                    **url_properties(url),
                    "captured": record.get("capture_status") == "captured",
                    "context_ids": record.get("_context_ids", []), "oversized": len(encode(record)) > SHARD_BYTES,
                })
            key = identity("inventory-batch-v4", generation, sequence, reference)
            previous = self.connection.execute(
                "SELECT id FROM graph_inventory_outbox WHERE generation=? AND sequence=?",
                (generation, sequence),
            ).fetchone()
            if previous and previous[0] != key:
                raise ValueError("Inventory batch identity conflict")
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_inventory_outbox(id,generation,sequence,shard,metadata) VALUES (?,?,?,?,?)",
                (key, generation, sequence, reference, json.dumps(metadata, separators=(",", ":"))),
            )
            result.append(key)
        return result

    def pending(self, limit=1):
        if not 1 <= limit <= 500:
            raise ValueError("Invalid inventory obligation limit")
        return self.connection.execute(
            "SELECT id,generation,sequence,shard,metadata FROM graph_inventory_outbox "
            "WHERE state='pending' ORDER BY generation,sequence LIMIT ?", (limit,),
        ).fetchall()

    def deliver(self, session, obligation):
        key, generation, sequence, shard, metadata = obligation
        with phase("delivery_prepare"):
            records = json.loads(metadata)
        count("records", len(records))
        count("metadata_bytes", len(metadata.encode()))

        if len(records) > 500 or len(metadata.encode()) > 4 * 1024 * 1024:
            raise ValueError("Inventory publication payload exceeds batch budget")

        @unit_of_work(timeout=graph_timeouts().write)
        def publish(tx):
            count("neo4j_attempts")
            generation_row = tx.run(
                "MATCH (g:GraphInventoryGeneration {id:$generation}) "
                "SET g.lock=coalesce(g.lock,0)+1 RETURN g.state AS state",
                generation=generation,
            ).single()
            receipt = tx.run(
                "MATCH (r:GraphInventoryBatch {id:$id}) "
                "RETURN r.shard AS shard,r.sequence AS sequence,r.generation AS generation",
                id=key,
            ).single()
            if receipt:
                if (receipt["shard"], receipt["sequence"], receipt["generation"]) != (shard, sequence, generation):
                    raise InventoryConflict("Inventory receipt identity conflict")
                return "replay"
            if generation_row is None or generation_row["state"] != "staging":
                raise InventoryConflict("Inventory generation is not staging")
            tx.run(
                "UNWIND $rows AS row MERGE (n:GraphInventoryFact {id:row.id}) "
                "ON CREATE SET n += row", rows=records,
            ).consume()
            scopes = {(row["url"], row["kind"]): {"id": identity("inventory-scope", generation, row["url"], row["kind"]),
                                   "generation": generation, "url": row["url"], "kind": row["kind"],
                                   **url_properties(row["url"])} for row in records}
            tx.run(
                "UNWIND $rows AS row MERGE (s:GraphInventoryScope {id:row.id}) ON CREATE SET s += row",
                rows=list(scopes.values()),
            ).consume()
            memberships = [{**row, "contexts": [{"id": identity("inventory-membership", generation, context, row["kind"]),
                                                  "capture_id": context} for context in row["context_ids"]]}
                           for row in records if row["context_ids"]]
            if memberships:
                tx.run(
                    "UNWIND $rows AS row MATCH (f:GraphInventoryFact {id:row.id}) "
                    "UNWIND row.contexts AS document MATCH (c:GraphInventoryCapture {id:document.capture_id}) "
                    "MERGE (m:GraphInventoryMembership {id:document.id}) ON CREATE SET "
                    "m.generation=row.generation,m.capture_id=c.id,m.kind=row.kind,m.url=c.url,"
                    "m.reverse_host=c.reverse_host,m.port=c.port,m.scheme=c.scheme,m.path=c.path "
                    "MERGE (f)-[:IN_DOCUMENT]->(c)", rows=memberships,
                ).consume()
            tx.run(
                "MERGE (r:GraphInventoryBatch {id:$id}) "
                "ON CREATE SET r.generation=$generation,r.sequence=$sequence,r.shard=$shard,r.slot_id=$slot",
                id=key, generation=generation, sequence=sequence, shard=shard,
                slot=identity("inventory-slot-v4", generation, sequence),
            ).consume()

            return "write"

        with phase("neo4j_write"):
            mode = session.execute_write(publish)
        label(delivery=mode)
        # Remote commit is durable first. Replaying after a local rollback is idempotent.
        with phase("sqlite_ack"):
            self.connection.execute(
                "UPDATE graph_inventory_outbox SET state='delivered',metadata='[]' WHERE id=?", (key,)
            )
