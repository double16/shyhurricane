"""Independent, bounded maintenance of retired graph generations."""

import logging
import threading
import time

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.coverage_repair import CoverageRepair
from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.lookup import migrate_lookup
from shyhurricane.graph.storage_maintenance import StorageMaintenance

logger = logging.getLogger(__name__)
OPERATION_BUDGET_SECONDS = 30


class GraphMaintenance:
    """One server-owned thread, driver, and retry schedule; never affects readiness."""

    def __init__(self, location, ready, *, artifact_db=None):
        self.store = GraphStore(location)
        self.ready = ready
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="graph-maintenance", daemon=True)
        self.failures = {"cleanup": 0, "lookup": 0}
        self.next_attempt = {"cleanup": 0.0, "lookup": 0.0}
        self.coverage_repair = CoverageRepair(artifact_db) if artifact_db is not None else None
        if self.coverage_repair is not None:
            self.failures["coverage"] = 0
            self.next_attempt["coverage"] = 0.0
        self.storage_maintenance = StorageMaintenance(artifact_db) if artifact_db is not None else None
        if self.storage_maintenance is not None:
            self.failures["storage"] = 0
            self.next_attempt["storage"] = 0.0
        self.lookup_batch_size = 500

    def start(self):
        self.thread.start()

    def close(self, deadline):
        self.stop_event.set()
        self.thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.thread.is_alive():
            logger.warning("Graph maintenance still stopping after shutdown deadline")

    def tick(self):
        """Give cleanup and lookup independent budgets and retry schedules."""
        # Cleanup runs first so slow lookup/commit work cannot consume its budget.
        for operation in tuple(self.next_attempt):
            if self.stop_event.is_set():
                return 60
            started = time.monotonic()
            if started < self.next_attempt[operation]:
                continue
            deadline = started + OPERATION_BUDGET_SECONDS
            delay = 60
            try:
                if operation == "cleanup":
                    self.store.expire_query_pins(timeout=max(0.001, deadline - time.monotonic()))
                    summary = self.store.cleanup(deadline=deadline, stop_event=self.stop_event)
                    logger.info(
                        "Graph maintenance operation=cleanup selected=%s completed=%s deleted=%s seconds=%.3f "
                        "next_attempt_seconds=60",
                        summary["selected"], summary["completed"], summary["deleted"], time.monotonic() - started,
                    )
                elif operation == "storage":
                    result = self.storage_maintenance.tick(self.stop_event)
                    if result and (result["pending"] or result.get("deferred", False)):
                        delay = 1
                elif operation == "coverage":
                    self.coverage_repair.tick(self.stop_event)
                else:
                    migrated = migrate_lookup(
                        self.store, deadline, self.stop_event, batch_size=self.lookup_batch_size,
                    )
                    if time.monotonic() - started > OPERATION_BUDGET_SECONDS / 2:
                        self.lookup_batch_size = max(1, self.lookup_batch_size // 2)
                    logger.info(
                        "Graph maintenance operation=%s migrated=%s batch_size=%s seconds=%.3f "
                        "next_attempt_seconds=60",
                        operation, migrated, self.lookup_batch_size, time.monotonic() - started,
                    )
                self.failures[operation] = 0
            except Exception as error:
                if operation == "lookup" and isinstance(error, Neo4jError):
                    code = error.code or ""
                    if "TransactionTimedOut" in code or code.endswith("MemoryPoolOutOfMemoryError"):
                        self.lookup_batch_size = max(1, self.lookup_batch_size // 2)
                self.failures[operation] += 1
                delay = min(900, 60 * 2 ** min(self.failures[operation] - 1, 4))
                logger.warning(
                    "Graph maintenance failed operation=%s seconds=%.3f failures=%s batch_size=%s "
                    "next_attempt_seconds=%s",
                    operation, time.monotonic() - started, self.failures[operation], self.lookup_batch_size,
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
