"""Publication estimates and nonblocking monitor-cache behavior."""

from types import SimpleNamespace

from shyhurricane.graph.statistics import summarize_captures
from shyhurricane.graph.status import StatisticsCache


def capture(key="GET /", stamp=1, entities=10, relationships=20, **extra):
    return {
        "resource_key": key,
        "observed_at": stamp,
        "entity_estimate": entities,
        "relationship_estimate": relationships,
        **extra,
    }


def test_estimates_sum_capture_summaries_and_preserve_latest_ties():
    result = summarize_captures(
        [
            capture(published_at=10, gaps=["gap"]),
            capture(stamp=2, summarized=True, budget_limited=True),
            capture(stamp=2),
            capture("GET /other", entities=None, relationships=None),
        ]
    )
    assert result["entities"] == 30 and result["relationships"] == 60
    assert result["captures"] == 4 and result["incomplete_captures"] == 1
    assert result["last_published_at"] == 10 and result["approximate"]
    current = result["current"]
    assert current["entity_estimate"] == 20 and current["captures"] == 3
    assert current["resources"] == 2 and current["covered_captures"] == 2
    assert current["summarized_captures"] == current["budget_limited_captures"] == 1
    assert not current["coverage_complete"]
    assert summarize_captures([])["entities"] == 0
    legacy = summarize_captures([capture(entities=None)])
    assert legacy["entities"] is None and legacy["relationships"] is None


async def test_cache_never_blocks_or_runs_duplicate_refreshes_and_retains_stale_values():
    calls = []
    store = SimpleNamespace(statistics=lambda: calls.append(1) or {"entities": 42})
    cache = StatisticsCache()
    assert cache.snapshot(store, False)["statistics_stale"] and cache.task is None
    first = cache.snapshot(store, True)
    assert first["statistics_refreshed_at"] is None and "entities" not in first
    task = cache.task
    cache.snapshot(store, True)
    assert cache.task is task
    await task
    assert calls == [1]
    assert not cache.snapshot(store, True)["statistics_stale"]
    assert cache.snapshot(store, False)["entities"] == 42
    cache.next_refresh = 0
    store.statistics = lambda: 1 / 0
    cache.snapshot(store, True)
    await cache.task
    failed = cache.snapshot(store, True)
    assert failed["entities"] == 42 and failed["statistics_stale"]
    assert failed["statistics_error"] == "ZeroDivisionError"
    cache.next_refresh = 0
    store.statistics = lambda: {"entities": 7}
    cache.snapshot(store, True)
    await cache.task
    assert cache.snapshot(store, True)["entities"] == 7
    assert "statistics_error" not in cache.snapshot(store, True)


def test_database_statistics_query_reads_capture_metadata_only(monkeypatch):
    from shyhurricane.graph.database import GraphStore

    store = GraphStore("bolt://unused")
    statements = []

    def read(statement):
        statements.append(statement)
        return [capture()]

    monkeypatch.setattr(store, "read", read)
    assert store.statistics()["entities"] == 10
    assert len(statements) == 1 and "GraphCapture" in statements[0]
    assert "GraphEntity" not in statements[0] and "RELATES" not in statements[0]
