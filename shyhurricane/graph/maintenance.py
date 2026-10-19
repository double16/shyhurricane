"""Independent, bounded maintenance of retired graph generations."""

import logging
import threading
import time

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.database import GraphStore

logger = logging.getLogger(__name__)
MIGRATION_ID = "cleanup_pending_v1"
OPERATION_BUDGET_SECONDS = 30


def migrate_cleanup(store, deadline, stop_event, *, batch_size=500):
    """Commit each ordered migration page and its cursor atomically."""
    migrated = 0
    for _ in range(10):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or stop_event.is_set():
            break
        with store.connect().session(database="neo4j") as session:
            with session.begin_transaction(timeout=min(store.timeouts.read, remaining)) as tx:
                marker = tx.run(
                    "MERGE (m:GraphState {id:$id}) "
                    "ON CREATE SET m.cursor='',m.complete=false "
                    "RETURN m.cursor AS cursor,m.complete AS complete", id=MIGRATION_ID,
                ).single()
                if marker["complete"]:
                    return migrated
                rows = list(tx.run(
                    "MATCH (p:GraphPublication) WHERE p.id>$after "
                    "RETURN p.id AS id ORDER BY p.id LIMIT $limit", after=marker["cursor"], limit=batch_size,
                ))
                tx.run(
                    "UNWIND $ids AS id MATCH (p:GraphPublication {id:id}) "
                    "WHERE p.state IN ['retired','abandoned'] AND coalesce(p.cleaned,false)=false "
                    "SET p.cleanup_lock=coalesce(p.cleanup_lock,0)+1 WITH p "
                    "WHERE p.state IN ['retired','abandoned'] AND coalesce(p.cleaned,false)=false "
                    "SET p:GraphCleanupPending", ids=[row["id"] for row in rows],
                ).consume()
                tx.run(
                    "MATCH (m:GraphState {id:$id}) SET m.cursor=$after,m.complete=$complete",
                    id=MIGRATION_ID, after=rows[-1]["id"] if rows else marker["cursor"],
                    complete=len(rows) < batch_size,
                ).consume()
        migrated += len(rows)
        logger.info("Graph cleanup migration scanned=%s complete=%s", migrated, len(rows) < batch_size)
        if len(rows) < batch_size:
            break
    return migrated


class GraphMaintenance:
    """One server-owned thread, driver, and retry schedule; never affects readiness."""

    def __init__(self, location, ready):
        self.store = GraphStore(location)
        self.ready = ready
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="graph-maintenance", daemon=True)
        self.failures = {"cleanup": 0, "migration": 0}
        self.next_attempt = {"cleanup": 0.0, "migration": 0.0}
        self.migration_batch_size = 500

    def start(self):
        self.thread.start()

    def close(self, deadline):
        self.stop_event.set()
        self.thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.thread.is_alive():
            logger.warning("Graph maintenance still stopping after shutdown deadline")

    def tick(self):
        """Give cleanup and migration independent budgets and retry schedules."""
        # Cleanup runs first so slow migration/commit work cannot consume its budget.
        for operation in ("cleanup", "migration"):
            if self.stop_event.is_set():
                return 60
            started = time.monotonic()
            if started < self.next_attempt[operation]:
                continue
            deadline = started + OPERATION_BUDGET_SECONDS
            delay = 60
            try:
                if operation == "cleanup":
                    summary = self.store.cleanup(deadline=deadline, stop_event=self.stop_event)
                    logger.info(
                        "Graph maintenance operation=cleanup selected=%s completed=%s deleted=%s seconds=%.3f "
                        "next_attempt_seconds=60",
                        summary["selected"], summary["completed"], summary["deleted"], time.monotonic() - started,
                    )
                else:
                    migrated = migrate_cleanup(
                        self.store, deadline, self.stop_event, batch_size=self.migration_batch_size,
                    )
                    if time.monotonic() - started > OPERATION_BUDGET_SECONDS / 2:
                        self.migration_batch_size = max(1, self.migration_batch_size // 2)
                    logger.info(
                        "Graph maintenance operation=migration migrated=%s batch_size=%s seconds=%.3f "
                        "next_attempt_seconds=60",
                        migrated, self.migration_batch_size, time.monotonic() - started,
                    )
                self.failures[operation] = 0
            except Exception as error:
                if operation == "migration" and isinstance(error, Neo4jError):
                    code = error.code or ""
                    if "TransactionTimedOut" in code or code.endswith("MemoryPoolOutOfMemoryError"):
                        self.migration_batch_size = max(1, self.migration_batch_size // 2)
                self.failures[operation] += 1
                delay = min(900, 60 * 2 ** min(self.failures[operation] - 1, 4))
                logger.warning(
                    "Graph maintenance failed operation=%s seconds=%.3f failures=%s batch_size=%s "
                    "next_attempt_seconds=%s",
                    operation, time.monotonic() - started, self.failures[operation], self.migration_batch_size,
                    delay, exc_info=True,
                )
            self.next_attempt[operation] = time.monotonic() + delay
        return max(0, min(self.next_attempt.values()) - time.monotonic())

    def run(self):
        try:
            while not self.stop_event.is_set():
                delay = self.tick() if self.ready() else 1
                self.stop_event.wait(delay)
        finally:
            self.store.close()
