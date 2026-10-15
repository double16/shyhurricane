"""Nonblocking graph status for HTTP and terminal monitoring."""

import asyncio
import time

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.persistent_queue import persistent_queue_path, read_active_queue_size


class StatisticsCache:
    """One background refresh per context; stale values remain available after failures."""

    def __init__(self):
        self.values = {}
        self.refreshed_at = None
        self.next_refresh = 0
        self.task = None
        self.error = None

    async def refresh(self, store):
        try:
            self.values = await asyncio.to_thread(store.statistics)
            self.refreshed_at = time.time()
            self.error = None
        except Exception as error:
            self.error = type(error).__name__
        finally:
            self.next_refresh = time.monotonic() + 60

    def snapshot(self, store, healthy):
        if healthy and time.monotonic() >= self.next_refresh and (self.task is None or self.task.done()):
            self.task = asyncio.create_task(self.refresh(store))
        age = max(0, time.time() - self.refreshed_at) if self.refreshed_at is not None else None
        return {
            **self.values,
            "statistics_refreshed_at": self.refreshed_at,
            "statistics_age_seconds": age,
            "statistics_stale": not healthy or self.error is not None or age is None or age >= 60,
            **({"statistics_error": self.error} if self.error else {}),
        }


async def graph_status(server_context) -> dict:
    store = getattr(server_context, "graph_store", None)
    monitor = getattr(server_context, "health_monitor", None)
    result = {"healthy": getattr(monitor, "neo4j_healthy", None), "queue_depth": 0}
    if store is None:
        return result

    def collect():
        details = {}
        path = persistent_queue_path(server_context.db, "graph_queue")
        if (path / "data.db").exists():
            details["queue_depth"] = read_active_queue_size(path)
        artifacts = ArtifactStore(server_context.db)
        try:
            details["analyses"] = artifacts.counts()
            details["backfill_started"] = (artifacts.root / "backfill.json").exists()
            details["unresolved_references"] = artifacts.connection.execute(
                "SELECT count(DISTINCT r.url) FROM refs r LEFT JOIN captures c ON r.url=c.url WHERE c.id IS NULL"
            ).fetchone()[0]
        finally:
            artifacts.close()
        return details

    cache = getattr(server_context, "_graph_statistics_cache", None)
    if cache is None:
        cache = StatisticsCache()
        server_context._graph_statistics_cache = cache
    result.update(cache.snapshot(store, result["healthy"]))
    last = result.get("last_published_at")
    result["seconds_since_publication"] = max(0, time.time() - last) if last else None
    try:
        result.update(await asyncio.to_thread(collect))
    except Exception as error:
        result["statistics_error"] = type(error).__name__
    return result
