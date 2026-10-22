import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shyhurricane.monitoring_qdrant import MonitorQdrantCache, bounded_collection_count, bounded_count


@pytest.mark.asyncio
async def test_cache_expiry_stale_retention_cooldown_and_recovery():
    now = [0.0]
    cache = MonitorQdrantCache(lambda: now[0])
    load = AsyncMock(return_value={"host": 3})
    assert await cache.get("domains", load, 300, {}) == {"host": 3}
    now[0] = 299
    assert await cache.get("domains", load, 300, {}) == {"host": 3}
    assert load.await_count == 1
    assert cache.freshness()["domains"] == {"status": "cached", "age_seconds": 299}
    now[0] = 300
    load.side_effect = ConnectionError("offline")
    assert await cache.get("domains", load, 300, {}) == {"host": 3}
    assert cache.freshness()["domains"] == {"status": "stale", "age_seconds": 300}
    now[0] = 359
    await cache.get("domains", load, 300, {})
    assert load.await_count == 2
    now[0] = 360
    load.side_effect = None
    load.return_value = {}
    assert await cache.get("domains", load, 300, {}) == {}
    assert cache.freshness()["domains"] == {"status": "cached", "age_seconds": 0}


@pytest.mark.asyncio
async def test_initial_failure_is_unavailable_and_samples_have_independent_intervals():
    now = [0.0]
    cache = MonitorQdrantCache(lambda: now[0])
    failed = AsyncMock(side_effect=RuntimeError("offline"))
    assert await cache.get("domains", failed, 300, ({}, {})) == ({}, {})
    assert cache.freshness()["domains"] == {"status": "unavailable", "age_seconds": None}
    load = AsyncMock(return_value=["url"])
    await cache.get("urls", load, 30, [])
    now[0] = 30
    await cache.get("urls", load, 30, [])
    await cache.get("domains", failed, 300, ({}, {}))
    assert failed.await_count == 1
    assert load.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_refreshes_are_coalesced_and_cancellation_propagates():
    cache = MonitorQdrantCache(lambda: 0)
    entered, release = asyncio.Event(), asyncio.Event()

    async def load():
        entered.set()
        await release.wait()
        return 42

    loader = AsyncMock(side_effect=load)
    first = asyncio.create_task(cache.get("count", loader, 300, 0))
    await entered.wait()
    second = asyncio.create_task(cache.get("count", loader, 300, 0))
    release.set()
    assert await asyncio.gather(first, second) == [42, 42]
    assert loader.await_count == 1
    entered.clear()
    release.clear()
    task = asyncio.create_task(cache.get("cancel", loader, 300, 0))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cache.samples["cancel"].retry_at == 0
    release.set()
    assert await cache.get("cancel", loader, 300, 0) == 42


@pytest.mark.asyncio
async def test_request_and_sample_timeouts_are_bounded(monkeypatch):
    timeout = asyncio.timeout
    deadlines = []

    def fast_timeout(seconds):
        deadlines.append(seconds)
        return timeout(0.01)

    monkeypatch.setattr(asyncio, "timeout", fast_timeout)

    async def blocked():
        await asyncio.Event().wait()

    store = SimpleNamespace(count_documents_async=blocked)
    with pytest.raises(TimeoutError):
        await bounded_count(store)
    cache = MonitorQdrantCache()
    assert await cache.get("blocked", blocked, 300, None) is None
    assert cache.freshness()["blocked"]["status"] == "unavailable"
    assert deadlines == [5, 10]


@pytest.mark.asyncio
async def test_bounded_count_preserves_exact_store_result_and_errors():
    store = SimpleNamespace(count_documents_async=AsyncMock(return_value=17))
    assert await bounded_count(store) == 17
    store.count_documents_async.side_effect = ConnectionError("offline")
    with pytest.raises(ConnectionError, match="offline"):
        await bounded_count(store)


@pytest.mark.asyncio
@pytest.mark.parametrize("exists", [False, True])
async def test_primary_collection_count_handles_missing_and_populated_collections(exists):
    client = SimpleNamespace(
        collection_exists=AsyncMock(return_value=exists), count=AsyncMock(return_value=SimpleNamespace(count=193)),
    )
    assert await bounded_collection_count(client, "finding") == (193 if exists else 0)
    client.collection_exists.assert_awaited_once_with(collection_name="finding")
    if exists:
        client.count.assert_awaited_once_with(collection_name="finding", exact=True, timeout=5)
    else:
        client.count.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["collection_exists", "count"])
async def test_primary_collection_count_does_not_hide_failures(stage):
    client = SimpleNamespace(collection_exists=AsyncMock(return_value=True), count=AsyncMock())
    getattr(client, stage).side_effect = ConnectionError("offline")
    with pytest.raises(ConnectionError, match="offline"):
        await bounded_collection_count(client, "finding")


@pytest.mark.asyncio
async def test_primary_collection_count_has_deadline(monkeypatch):
    timeout = asyncio.timeout
    monkeypatch.setattr(asyncio, "timeout", lambda seconds: timeout(0.01))

    async def blocked(**kwargs):
        await asyncio.Event().wait()

    with pytest.raises(TimeoutError):
        await bounded_collection_count(SimpleNamespace(collection_exists=blocked), "finding")
