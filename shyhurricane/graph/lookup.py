"""Indexed URL and context access paths, with checkpointed compatibility backfill."""

import time
from urllib.parse import urlsplit

from shyhurricane.graph.model import identity

MIGRATION_ID = "graph_lookup_v1"
LABELS = ("GraphEntity", "GraphPublication", "GraphCapture")


def reverse_host(url):
    """Terminate the reversed hostname to preserve DNS label boundaries."""
    return (urlsplit(url).hostname or "")[::-1] + "."


def context_records(owner, kind, urls):
    return [
        {"id": identity("context-lookup", kind, owner, url), "owner_id": owner,
         "owner_kind": kind, "url": url, "reverse_host": reverse_host(url)}
        for url in sorted(set(urls))
    ]


def write_contexts(tx, records):
    tx.run(
        "UNWIND $rows AS row MERGE (n:GraphContext {id:row.id}) SET n += row",
        rows=records,
    ).consume()


def migrate_lookup(store, deadline, stop_event, *, batch_size=500):
    """Backfill each metadata page and checkpoint in the same bounded transaction."""
    scanned = 0
    for _ in range(1000):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or stop_event.is_set():
            break
        with store.connect().session(database="neo4j") as session:
            with session.begin_transaction(timeout=min(store.timeouts.read, remaining)) as tx:
                marker = tx.run(
                    "MERGE (m:GraphState {id:$id}) ON CREATE SET m.stage=0,m.cursor='',m.complete=false "
                    "RETURN m.stage AS stage,m.cursor AS cursor,m.complete AS complete", id=MIGRATION_ID,
                ).single()
                if marker["complete"]:
                    break
                stage = marker["stage"]
                label = LABELS[stage]
                rows = list(tx.run(
                    f"MATCH (n:{label}) WHERE n.id>$after "
                    "RETURN n.id AS id,n.url AS url,n.context_urls AS contexts, "
                    "n.context_owner_id AS context_owner ORDER BY n.id LIMIT $limit",
                    after=marker["cursor"], limit=batch_size,
                ))
                if stage == 0:
                    tx.run(
                        "UNWIND $rows AS row MATCH (n:GraphEntity {id:row.id}) "
                        "SET n._reverse_host=row.host",
                        rows=[{"id": row["id"], "host": reverse_host(row["url"] or "")} for row in rows],
                    ).consume()
                records = [
                    record for row in rows if stage != 0 or row["context_owner"] is None
                    for record in context_records(row["id"], label, row["contexts"] or [])
                ]
                write_contexts(tx, records)
                finished = len(rows) < batch_size
                next_stage = stage + int(finished)
                tx.run(
                    "MATCH (m:GraphState {id:$id}) SET m.stage=$stage,m.cursor=$cursor,m.complete=$complete",
                    id=MIGRATION_ID, stage=next_stage,
                    cursor="" if finished else rows[-1]["id"], complete=next_stage == len(LABELS),
                ).consume()
                scanned += len(rows)
    return scanned
