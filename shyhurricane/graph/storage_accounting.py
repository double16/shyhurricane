"""Indexed, resumable artifact classification and reference-count reclamation."""

import time


def propagate(connection):
    job = connection.execute(
        "SELECT w.parent,w.after_child,n.retained,n.cached FROM graph_storage_work w "
        "JOIN graph_nodes n ON n.id=w.parent ORDER BY w.parent LIMIT 1"
    ).fetchone()
    if job is None:
        return False
    parent, after, retained, cached = job
    edge = connection.execute(
        "SELECT child,retained,cached FROM graph_edges WHERE parent=? AND child>? ORDER BY child LIMIT 1",
        (parent, after),
    ).fetchone()
    if edge is None:
        connection.execute("DELETE FROM graph_storage_work WHERE parent=?", (parent,))
    else:
        child, previous_retained, previous_cached = edge
        if (retained, cached) != (previous_retained, previous_cached):
            connection.execute(
                "UPDATE graph_edges SET retained=?,cached=? WHERE parent=? AND child=?",
                (retained, cached, parent, child),
            )
        connection.execute("UPDATE graph_storage_work SET after_child=? WHERE parent=?", (child, parent))
    return True


def retire(connection, reference):
    """Logical removal is immediate; outgoing edges are released one at a time."""
    connection.execute("UPDATE graph_nodes SET created=0 WHERE id=?", (reference,))
    connection.execute(
        "UPDATE graph_nodes SET retiring=1 WHERE id=? AND owners=0 AND caches=0 AND incoming=0 AND retiring=0",
        (reference,),
    )


def collect_node(connection):
    row = connection.execute(
        "SELECT id FROM graph_nodes INDEXED BY graph_node_retiring WHERE retiring=1 ORDER BY id LIMIT 1"
    ).fetchone()
    if row is None:
        row = connection.execute(
            "SELECT id FROM graph_nodes INDEXED BY graph_node_unused "
            "WHERE owners=0 AND caches=0 AND incoming=0 AND retiring=0 AND created<? "
            "ORDER BY created,id LIMIT 1",
            (time.time() - 3600,),
        ).fetchone()
        if row is None:
            return False
        retire(connection, row[0])
    reference = row[0]
    edge = connection.execute(
        "SELECT child FROM graph_edges WHERE parent=? ORDER BY child LIMIT 1", (reference,)
    ).fetchone()
    if edge:
        connection.execute("DELETE FROM graph_edges WHERE parent=? AND child=?", (reference, edge[0]))
    else:
        connection.execute("DELETE FROM graph_nodes WHERE id=? AND owners=0 AND caches=0 AND incoming=0", (reference,))
    return True


def collect_blob(connection):
    row = connection.execute(
        "SELECT digest FROM graph_blob_usage INDEXED BY graph_blob_unused WHERE node_refs=0 ORDER BY digest LIMIT 1"
    ).fetchone()
    if row is None:
        return False
    connection.execute(
        "DELETE FROM graph_blobs WHERE digest=? AND EXISTS "
        "(SELECT 1 FROM graph_blob_usage WHERE digest=? AND node_refs=0)",
        (row[0], row[0]),
    )
    return True


def evict(connection, budget):
    if connection.execute("SELECT cached FROM graph_storage_totals WHERE id=1").fetchone()[0] <= budget:
        return False
    row = connection.execute("SELECT key,ref FROM graph_cache ORDER BY accessed,key LIMIT 1").fetchone()
    if row is None:
        return False
    key, _ = row
    connection.execute("DELETE FROM graph_cache WHERE key=?", (key,))
    # Preserve staging/read grace: a caller may be preparing a new checkpoint.
    return True


def pending(connection, budget):
    state = connection.execute("SELECT pending,retiring,cached FROM graph_storage_totals WHERE id=1").fetchone()
    if state[0] or state[1]:
        return True
    if state[2] > budget and connection.execute("SELECT 1 FROM graph_cache LIMIT 1").fetchone():
        return True
    if connection.execute(
        "SELECT 1 FROM graph_nodes INDEXED BY graph_node_unused "
        "WHERE owners=0 AND caches=0 AND incoming=0 AND retiring=0 AND created<? LIMIT 1",
        (time.time() - 3600,),
    ).fetchone():
        return True
    return (
        connection.execute(
            "SELECT 1 FROM graph_blob_usage INDEXED BY graph_blob_unused WHERE node_refs=0 LIMIT 1"
        ).fetchone()
        is not None
    )


def maintain(connection, budget, batch=500):
    """Each work item changes one edge, node, or cache root; callers commit sub-batches."""
    kind = connection.execute("SELECT next_kind FROM graph_storage_totals WHERE id=1").fetchone()[0]
    processed, idle = 0, 0
    while processed < batch and idle < 4:
        operation = (propagate, lambda db: evict(db, budget), collect_node, collect_blob)[kind]
        changed = operation(connection)
        kind = (kind + 1) % 4
        if changed:
            processed += 1
            idle = 0
        else:
            idle += 1
    connection.execute(
        "UPDATE graph_storage_totals SET next_kind=?,last_progress=CASE WHEN ?>0 THEN ? ELSE last_progress END WHERE id=1",
        (kind, processed, time.time()),
    )
    return {"processed": processed, "pending": pending(connection, budget)}


def statistics(connection, budget):
    logical, stored, retained, cached, jobs, retiring, progress = connection.execute(
        "SELECT logical,stored,retained,cached,pending,retiring,last_progress FROM graph_storage_totals WHERE id=1"
    ).fetchone()
    page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    return {
        "logical_payload_bytes": logical,
        "stored_payload_bytes": stored,
        "retained_bytes": retained,
        "cache_bytes": cached,
        "staged_bytes": stored - retained - cached,
        "cache_budget_bytes": budget,
        "accounting_pending": jobs > 0,
        "pending_work_count": jobs + retiring,
        "last_maintenance_progress_at": progress,
        "database_bytes": connection.execute("PRAGMA page_count").fetchone()[0] * page_size,
        "reclaimable_bytes": connection.execute("PRAGMA freelist_count").fetchone()[0] * page_size,
    }
