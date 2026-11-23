"""Independent, bounded maintenance of retired graph generations."""

import logging
import sqlite3
import threading
import time
from contextlib import closing

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.inventory_cleanup import InventoryCleanup
from shyhurricane.graph.lookup import migrate_lookup
from shyhurricane.graph.storage_maintenance import StorageMaintenance

logger = logging.getLogger(__name__)
OPERATION_BUDGET_SECONDS = 30


class GraphMaintenance:
    """One server-owned thread, driver, and retry schedule; never affects readiness."""

    def __init__(self, location, ready, *, artifact_db=None, disk_snapshot=None):
        self.store = GraphStore(location)
        self.ready = ready
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="graph-maintenance", daemon=True)
        self.failures = {"cleanup": 0, "lookup": 0}
        self.next_attempt = {"cleanup": 0.0, "lookup": 0.0}
        self.storage_maintenance = StorageMaintenance(artifact_db) if artifact_db is not None else None
        self.inventory_cleanup = (
            InventoryCleanup(self.store, self.storage_maintenance.root / "artifacts.sqlite")
            if self.storage_maintenance is not None else None
        )
        if self.inventory_cleanup is not None:
            self.failures["inventory"] = 0
            self.next_attempt["inventory"] = 0
        if self.storage_maintenance is not None:
            self.failures["storage"] = 0
            self.next_attempt["storage"] = 0.0
        self.disk_snapshot = disk_snapshot or (lambda: {})
        self.inventory_last_pass = None
        self.inventory_reason = None
        self.inventory_completed_epoch = None
        self.lookup_batch_size = 500

    def inventory_schedule(self, now):
        """Prefer idle reclamation, retaining bounded fallback and genuine pressure work."""
        disk = self.disk_snapshot() or {}
        pressure = disk.get("state") == "paused" and disk.get("error") is None
        if pressure:
            return "disk_pressure", 5
        active = True
        try:
            path = self.storage_maintenance.root / "artifacts.sqlite"
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.set_progress_handler(lambda: 1, 100000)
                completed = connection.execute(
                    "SELECT coalesce(max(id),0) FROM graph_epochs WHERE phase='done'"
                ).fetchone()[0]
                changed = self.inventory_completed_epoch is not None and completed > self.inventory_completed_epoch
                self.inventory_completed_epoch = completed
                active = bool(connection.execute(
                    "SELECT 1 FROM graph_epochs WHERE phase NOT IN ('done','failed') LIMIT 1"
                ).fetchone())
        except sqlite3.Error:
            pass
        else:
            if changed:
                return "epoch_complete", 1
        if not active:
            return "idle", 1
        if self.inventory_last_pass is None or now - self.inventory_last_pass >= 1800:
            return "fallback", 60
        return "active_epoch", 60

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
                elif operation == "inventory":
                    reason, cadence = self.inventory_schedule(started)
                    if reason != self.inventory_reason:
                        logger.info("Graph inventory cleanup scheduling reason=%s", reason)
                        self.inventory_reason = reason
                    if reason == "active_epoch":
                        logger.debug("Graph inventory cleanup deferred reason=%s", reason)
                    else:
                        self.inventory_last_pass = started
                        try:
                            pending = self.inventory_cleanup.step(deadline=started + 2)
                        except Neo4jError as error:
                            if "TransactionTimedOut" not in (error.code or ""):
                                raise
                            logger.info("Graph inventory cleanup lock/budget deferred reason=%s", reason)
                            pending = True
                        delay = cadence if pending or reason == "disk_pressure" else 60
                elif operation == "storage":
                    result = self.storage_maintenance.tick(self.stop_event)
                    if result and (result["pending"] or result.get("deferred", False)):
                        delay = result.get("next_attempt_seconds", 1)
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
            if self.storage_maintenance is not None:
                self.storage_maintenance.close()
            self.store.close()
