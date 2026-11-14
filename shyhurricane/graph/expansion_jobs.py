"""Durable expansion acceptance and artifact ownership, independent of wakeup tickets."""

from shyhurricane.graph.blob_store import owner_triggers
from shyhurricane.graph.inventory_updates import enqueue as enqueue_status
from shyhurricane.graph.model import identity


def accept_job(connection, item, queue_id):
    generation = item.get("inventory_generation")
    key = identity("expand", item["id"], item["analysis_unit_id"], generation)
    connection.execute(
        "INSERT OR IGNORE INTO graph_expansions(id,capture_id,unit_id,state,artifact,generation) "
        "VALUES (?,?,?,'pending',?,?)",
        (key, item["id"], item["analysis_unit_id"], item.get("inventory_artifact"), generation),
    )
    connection.execute(
        "UPDATE graph_expansions SET state='pending',next_attempt=0,checkpoint='' WHERE id=? AND state='failed'",
        (key,),
    )
    if queue_id is not None:
        connection.execute("INSERT OR IGNORE INTO graph_expansion_receipts VALUES (?,?)", (queue_id, key))
    state = connection.execute("SELECT state FROM graph_expansions WHERE id=?", (key,)).fetchone()[0]
    if state == "pending":
        enqueue_status(connection, item["analysis_unit_id"], generation, "pending")
    return key



def initialize_jobs(connection):
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS graph_expansions (id TEXT PRIMARY KEY,capture_id TEXT,unit_id TEXT,"
        "state TEXT,error TEXT DEFAULT '',next_attempt REAL DEFAULT 0,checkpoint TEXT DEFAULT '',artifact TEXT,generation TEXT);"
        "CREATE TABLE IF NOT EXISTS graph_expansion_receipts (queue_id INTEGER PRIMARY KEY,job_id TEXT);"
    )

    owner_triggers(connection, "graph_expansions", "checkpoint", "id")
    owner_triggers(connection, "graph_expansions", "artifact", "id")

