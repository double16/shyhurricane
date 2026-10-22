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


async def test_cache_logs_failure_code_and_clears_it_after_recovery(caplog):
    from neo4j.exceptions import ClientError

    class StatisticsFailure(ClientError):
        @property
        def code(self):
            return "Neo.ClientError.Transaction.TransactionTimedOut"

    error = StatisticsFailure("Statistics deadline exceeded")

    def fail():
        raise error

    store = SimpleNamespace(statistics=fail)
    cache = StatisticsCache()
    cache.snapshot(store, True)
    await cache.task
    failed = cache.snapshot(store, True)
    assert failed["statistics_error"] == "StatisticsFailure"
    assert failed["statistics_error_code"] == error.code
    record = next(record for record in caplog.records if "Unable to refresh graph statistics" in record.message)
    assert record.exc_info[1] is error
    assert "Statistics deadline exceeded" in caplog.text
    cache.next_refresh = 0
    store.statistics = lambda: {"entities": 0}
    cache.snapshot(store, True)
    await cache.task
    recovered = cache.snapshot(store, True)
    assert "statistics_error_code" not in recovered and "statistics_error" not in recovered


def test_database_statistics_query_reads_capture_metadata_only(monkeypatch):
    from shyhurricane.graph.database import GraphStore

    store = GraphStore("bolt://unused")
    statements = []

    def read(statement, **kwargs):
        assert kwargs == {"timeout": 5}
        statements.append(statement)
        return [capture()]

    monkeypatch.setattr(store, "read", read)
    assert store.statistics()["entities"] == 10
    assert len(statements) == 1 and "GraphCapture" in statements[0]
    assert "GraphEntity" not in statements[0] and "RELATES" not in statements[0]


async def test_statistics_refresh_interval_and_reference_namespace(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("shyhurricane.graph.status.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("shyhurricane.graph.status.time.time", lambda: clock[0])
    cache = StatisticsCache(prefix="reference_statistics")
    calls = []
    store = SimpleNamespace(statistics=lambda: calls.append(1) or {"unresolved_references": 3})
    cache.snapshot(store, True)
    await cache.task
    assert cache.next_refresh == 1300
    clock[0] = 1299
    assert not cache.snapshot(store, True)["reference_statistics_stale"]
    assert len(calls) == 1
    clock[0] = 1300
    assert cache.snapshot(store, True)["reference_statistics_stale"]
    await cache.task
    assert len(calls) == 2
    assert cache.snapshot(store, True)["reference_statistics_age_seconds"] == 0


def test_reference_counts_distinct_missing_urls_without_migration(graph_paths):
    import sqlite3

    from shyhurricane.graph.status import ReferenceStatistics

    path = graph_paths / "graph_state" / "artifacts.sqlite"
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE refs(url TEXT,capture_id TEXT);"
            "CREATE TABLE captures(id TEXT,url TEXT);"
        )
        connection.executemany("INSERT INTO refs VALUES (?,?)", [
            ("missing", "one"), ("missing", "two"), ("known", "one"), (None, "one")
        ])
        connection.executemany("INSERT INTO captures VALUES (?,?)", [("one", "known"), ("two", "known")])
    assert ReferenceStatistics("db").statistics() == {"unresolved_references": 1}
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall() == []
        connection.execute("DELETE FROM refs")
    assert ReferenceStatistics("db").statistics() == {"unresolved_references": 0}


async def test_reference_failure_is_cached_separately_and_recovers(graph_paths):
    from shyhurricane.graph.status import ReferenceStatistics

    cache = StatisticsCache(prefix="reference_statistics")
    cache.values = {"unresolved_references": 7}
    cache.snapshot(ReferenceStatistics("db"), True)
    await cache.task
    failed = cache.snapshot(ReferenceStatistics("db"), True)
    assert failed["unresolved_references"] == 7
    assert failed["reference_statistics_error"] == "OperationalError"
    assert failed["reference_statistics_stale"] and "statistics_error" not in failed
    assert not (graph_paths / "graph_state").exists()
    cache.next_refresh = 0
    cache.snapshot(SimpleNamespace(statistics=lambda: {"unresolved_references": 0}), True)
    await cache.task
    assert "reference_statistics_error" not in cache.snapshot(None, False)


def test_reference_deadline_interrupts_and_closes_connection(monkeypatch, graph_paths):
    from unittest.mock import MagicMock

    import pytest

    from shyhurricane.graph import status

    connection = MagicMock()
    connection.execute.side_effect = [None, status.sqlite3.OperationalError("interrupted")]
    monkeypatch.setattr(status.sqlite3, "connect", lambda *args, **kwargs: connection)
    clock = iter([0, 6])
    monkeypatch.setattr(status.time, "monotonic", lambda: next(clock))
    with pytest.raises(status.sqlite3.OperationalError, match="interrupted"):
        status.ReferenceStatistics("db").statistics()
    callback, frequency = connection.set_progress_handler.call_args.args
    assert callback() == 1 and frequency == 10000
    connection.close.assert_called_once()


async def test_activity_baselines_advances_idle_reset_missing_and_outage(monkeypatch):
    from shyhurricane.graph.status import ActivityCache

    clock = [1000.0]
    monkeypatch.setattr("shyhurricane.graph.status.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("shyhurricane.graph.status.time.time", lambda: clock[0])
    cache = ActivityCache()
    store = SimpleNamespace(activity=lambda: {"publication_revision": 10})
    assert cache.snapshot(store, False)["activity_stale"] and cache.task is None
    first = cache.snapshot(store, True)
    assert first["seconds_since_observed_progress"] is None
    task = cache.task
    cache.snapshot(store, True)
    assert cache.task is task
    await task
    assert cache.values["publication_revision_delta"] is None
    assert cache.next_refresh == 1030
    clock[0] += 30
    store.activity = lambda: {"publication_revision": 13}
    await cache.refresh(store)
    observed = cache.snapshot(store, True)
    assert observed["publication_revision_delta"] == 3
    assert observed["seconds_since_observed_progress"] == 0
    clock[0] += 30
    await cache.refresh(store)
    idle = cache.snapshot(store, True)
    assert idle["publication_revision_delta"] == 0 and idle["seconds_since_observed_progress"] == 30

    def fail():
        raise RuntimeError("offline")

    store.activity = fail
    await cache.refresh(store)
    failed = cache.snapshot(store, True)
    assert failed["activity_stale"] and failed["activity_error"] == "RuntimeError"
    assert failed["publication_revision"] == 13
    assert failed["seconds_since_observed_progress"] == 30
    store.activity = lambda: {"publication_revision": 2}
    await cache.refresh(store)
    reset = cache.snapshot(store, True)
    assert reset["publication_revision_delta"] is None and reset["seconds_since_observed_progress"] is None
    assert "activity_error" not in reset
    store.activity = lambda: {"publication_revision": None}
    await cache.refresh(store)
    assert cache.values["publication_revision_delta"] is None
    store.activity = lambda: {"publication_revision": 0}
    await cache.refresh(store)
    assert cache.values["publication_revision"] == 0 and cache.values["publication_revision_delta"] is None


def test_activity_query_reads_only_single_indexed_state_with_deadline(monkeypatch):
    from shyhurricane.graph.database import GraphStore

    store = GraphStore("bolt://unused")
    rows = []

    def read(statement, **kwargs):
        assert statement == "MATCH (s:GraphState {id:'publication_revision'}) RETURN s.value AS revision"
        assert kwargs == {"timeout": 2}
        return rows

    monkeypatch.setattr(store, "read", read)
    assert store.activity() == {"publication_revision": None}
    rows.append({"revision": 123})
    assert store.activity() == {"publication_revision": 123}
