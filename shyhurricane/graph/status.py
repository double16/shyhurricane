"""Nonblocking graph status for HTTP and terminal monitoring."""

import asyncio
import logging
import sqlite3
import time

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.epochs import epoch_status
from shyhurricane.graph.storage_maintenance import StorageMaintenance
from shyhurricane.persistent_queue import persistent_queue_path, read_active_queue_size

logger = logging.getLogger(__name__)


class StatisticsCache:
    """One background refresh per context; stale values remain available after failures."""

    def __init__(self, prefix="statistics", interval=300, method="statistics"):
        self.prefix = prefix
        self.interval = interval
        self.method = method
        self.values = {}
        self.refreshed_at = None
        self.next_refresh = 0
        self.task = None
        self.error = None
        self.error_code = None

    async def refresh(self, store):
        try:
            self.values = await asyncio.to_thread(getattr(store, self.method))
            self.refreshed_at = time.time()
            self.error = None
            self.error_code = None
        except Exception as error:
            self.error = type(error).__name__
            self.error_code = getattr(error, "code", None)
            logger.warning("Unable to refresh graph %s", self.prefix, exc_info=True)
        finally:
            self.next_refresh = time.monotonic() + self.interval

    def snapshot(self, store, healthy):
        if healthy and time.monotonic() >= self.next_refresh and (self.task is None or self.task.done()):
            self.task = asyncio.create_task(self.refresh(store))
        age = max(0, time.time() - self.refreshed_at) if self.refreshed_at is not None else None
        return {
            **self.values,
            f"{self.prefix}_refreshed_at": self.refreshed_at,
            f"{self.prefix}_age_seconds": age,
            f"{self.prefix}_stale": not healthy or self.error is not None or age is None or age >= self.interval,
            **({f"{self.prefix}_error": self.error} if self.error else {}),
            **({f"{self.prefix}_error_code": self.error_code} if self.error_code else {}),
        }


class ActivityCache(StatisticsCache):
    """Observe committed publication progress without implying that idle means stalled."""

    def __init__(self):
        super().__init__(prefix="activity", interval=30, method="activity")
        self.progress_at = None

    async def refresh(self, store):
        previous = self.values.get("publication_revision")
        await super().refresh(store)
        if self.error is not None:
            return
        revision = self.values.get("publication_revision")
        delta = revision - previous if revision is not None and previous is not None and revision >= previous else None
        if delta is None:
            self.progress_at = None
        elif delta > 0:
            self.progress_at = time.monotonic()
        self.values["publication_revision_delta"] = delta

    def snapshot(self, store, healthy):
        result = super().snapshot(store, healthy)
        result["seconds_since_observed_progress"] = (
            max(0, time.monotonic() - self.progress_at) if self.progress_at is not None else None
        )
        return result


class ReferenceStatistics:
    """Read expensive reference counts without initializing or migrating live artifacts."""

    def __init__(self, db):
        self.path = persistent_queue_path(db, "graph_state") / "artifacts.sqlite"

    def statistics(self):
        started = time.monotonic()
        connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.set_progress_handler(lambda: int(time.monotonic() - started >= 5), 10000)
            count = connection.execute(
                "SELECT count(*) FROM (SELECT DISTINCT url FROM refs) r "
                "WHERE r.url IS NOT NULL AND NOT EXISTS (SELECT 1 FROM captures c WHERE c.url=r.url)"
            ).fetchone()[0]
            return {"unresolved_references": count}
        finally:
            connection.close()


async def graph_status(server_context, *, include_estimates=True) -> dict:
    store = getattr(server_context, "graph_store", None)
    monitor = getattr(server_context, "health_monitor", None)
    result = {"healthy": getattr(monitor, "neo4j_healthy", None), "queue_depth": 0}
    if store is None:
        return result
    # Connection configuration remains useful even when the statistics query fails.
    result["uri"] = getattr(store, "uri", None)

    def collect():
        from shyhurricane.investigation.storage import correlation_status

        details = {"investigation": correlation_status(server_context.db)}
        path = persistent_queue_path(server_context.db, "graph_queue")
        if (path / "data.db").exists():
            details["queue_depth"] = read_active_queue_size(path)
        artifacts = ArtifactStore(server_context.db)
        try:
            details["analyses"] = artifacts.counts()
            details["epoch"] = epoch_status(artifacts.connection)
            details["backfill_started"] = bool(artifacts.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='backfill'"
            ).fetchone())
            if artifacts.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_continuations'"
            ).fetchone():
                counts = {"pending": 0, "running": 0, "failed": 0}
                counts.update(artifacts.connection.execute(
                    "SELECT state,count(*) FROM graph_continuations "
                    "WHERE state IN ('pending','running','failed') GROUP BY state"
                ).fetchall())
                recent = artifacts.connection.execute(
                    "SELECT stage,contexts_done,contexts_total,updated_at FROM graph_continuations "
                    "ORDER BY updated_at DESC LIMIT 1"
                ).fetchone()
                if recent:
                    counts.update(stage=recent[0], contexts_completed=recent[1], contexts_discovered=recent[2],
                                  checkpoint_age_seconds=max(0, time.time() - recent[3]))
                details["continuations"] = counts
        finally:
            artifacts.close()
        return details

    activity = getattr(server_context, "_graph_activity_cache", None)
    if activity is None:
        activity = ActivityCache()
        server_context._graph_activity_cache = activity
    result.update(activity.snapshot(store, result["healthy"]))
    if include_estimates:
        cache = getattr(server_context, "_graph_statistics_cache", None)
        if cache is None:
            cache = StatisticsCache()
            server_context._graph_statistics_cache = cache
        result.update(cache.snapshot(store, result["healthy"]))
        result["uri"] = getattr(store, "uri", None) or result.get("uri")
        last = result.get("last_published_at")
        result["seconds_since_publication"] = max(0, time.time() - last) if last else None
    try:
        result.update(await asyncio.to_thread(collect))
    except Exception as error:
        result["statistics_error"] = type(error).__name__
    storage = getattr(server_context, "_graph_storage_cache", None)
    if storage is None:
        storage = StatisticsCache(prefix="storage", interval=60)
        server_context._graph_storage_cache = storage
    result["storage"] = storage.snapshot(StorageMaintenance(server_context.db), True)
    if include_estimates:
        references = getattr(server_context, "_graph_reference_cache", None)
        if references is None:
            references = StatisticsCache(prefix="reference_statistics")
            server_context._graph_reference_cache = references
        result.update(references.snapshot(ReferenceStatistics(server_context.db), True))
    return result
