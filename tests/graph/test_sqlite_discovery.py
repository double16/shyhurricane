"""Discovery reads stay selective, cancellable, and resumable on existing artifacts."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.manifest_query import manifest_query
from shyhurricane.graph.query import GraphQuery


@pytest.fixture
def populated(graph_paths, event):
    store = ArtifactStore("db")
    capture = store.register(event())
    unit = store.manifest.unit(capture["id"], "fixture", discovery="complete", flow="complete")
    for index in range(12):
        store.manifest.fact(unit, capture["id"], "field", {
            "id": str(index), "url": capture["data"]["url"], "role": "source", "name": str(index),
        })
    store.close()
    return capture


def test_read_only_artifacts_do_not_initialize_or_allow_writes(populated):
    # Opening artifacts must not create or alter schema; PRAGMA query_only also rejects writes.
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget())
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        reader.connection.execute("DELETE FROM captures")
    reader.close()


def test_selective_query_plan_and_continued_results(populated):
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget(seconds=30))
    statements = []
    reader.connection.set_trace_callback(statements.append)
    result = manifest_query(reader, "example.com", kind="field", url=populated["data"]["url"], limit=3)
    ids = [row["id"] for row in result["results"]]
    service = GraphQuery(None, artifacts=reader)
    while result["continuation_token"]:
        token = result["continuation_token"]
        result = service.continue_query(token, limit=3)
        assert service.continue_query(token, limit=3) == result
        ids.extend(row["id"] for row in result["results"])
    assert len(ids) == len(set(ids)) == 12
    candidate = next(sql for sql in statements if sql.startswith("SELECT f.id FROM"))
    plan = reader.connection.execute("EXPLAIN QUERY PLAN " + candidate).fetchall()
    assert any("graph_manifest_url" in row[3] for row in plan)
    assert not manifest_query(reader, "target.local", kind="field")["results"]
    assert not manifest_query(reader, "example.com", kind="field", role="sink")["results"]
    reader.close()


@pytest.mark.parametrize("stage", ["page", "coverage"])
def test_deadline_preserves_records_and_explicit_unknown_coverage(populated, monkeypatch, stage):
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget())
    original = reader.manifest.page
    calls = 0

    def page(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls > 1 and stage == "page":
            raise TimeoutError("deadline")
        rows, cursor = original(*args, **kwargs)
        # Simulate duplicate-heavy batches requiring another physical read.
        return rows, (cursor or rows[-1]["manifest_id"]) if rows else None

    monkeypatch.setattr(reader.manifest, "page", page)
    monkeypatch.setattr(reader.manifest, "coverage", MagicMock(side_effect=TimeoutError("deadline")))
    result = manifest_query(reader, "example.com", kind="field", limit=20)
    assert len(result["results"]) == 12
    assert result["coverage"] == {"discovery": "unknown", "flow": "unknown"}
    assert result["continuation_token"] and "time_limit" in result["truncation_reasons"]
    assert result["analysis_gaps"]
    reader.close()


def test_database_errors_are_not_timeouts_and_expired_reads_stop(populated):
    budget = QueryBudget()
    reader = ArtifactStore("db", readonly=True, budget=budget)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        reader.connection.execute("SELECT * FROM missing_table")
    budget.deadline = budget.started
    with pytest.raises(TimeoutError):
        reader.connection.execute("SELECT 1")
    reader.close()
    assert not budget.interrupts


def test_cancellation_interrupts_running_sqlite_and_closes_connection(populated):
    started = threading.Event()
    budget = QueryBudget()

    def run():
        reader = ArtifactStore("db", readonly=True, budget=budget)
        reader.connection.set_trace_callback(lambda sql: started.set())
        try:
            with pytest.raises(TimeoutError):
                reader.connection.execute(
                    "WITH RECURSIVE numbers(n) AS (VALUES(0) UNION ALL "
                    "SELECT n+1 FROM numbers WHERE n<1000000000) SELECT sum(n) FROM numbers"
                ).fetchone()
        finally:
            reader.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(run)
        assert started.wait(2)
        budget.cancel()
        future.result(timeout=2)
    assert not budget.interrupts


def test_lock_contention_is_bounded(populated, graph_paths):
    # Schema locks are not possible with the production WAL setup; an exclusive DELETE-mode
    # fixture exercises the bounded busy handler without modifying any live database.
    path = graph_paths / "graph_state" / "artifacts.sqlite"
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=DELETE")
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget())
    writer.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(TimeoutError):
            reader.connection.execute("SELECT * FROM captures").fetchall()
    finally:
        writer.rollback()
        writer.close()
        reader.close()


def test_sparse_physical_batches_resume_without_skipping_late_matches(populated):
    writer = ArtifactStore("db")
    unit = writer.manifest.unit(populated["id"], "sparse")
    # Stable IDs place all out-of-scope candidates before the one valid fact.
    from shyhurricane.graph.compact_manifest import term

    with writer.connection:
        for index in range(5002):
            inside = index == 5001
            target = populated["data"]["url"] if inside else "https://target.local/a"
            payload = {"id": "last" if inside else "outside", "kind": "symbol", "url": target}
            ref = writer.write(f"sparse-{inside}", payload)
            writer.connection.execute(
                "INSERT INTO graph_facts(id,unit,capture,kind_key,url_key,host_key,role_key,data,method,captured) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("zzz" if inside else f"000{index:06}", term(writer.connection, unit),
                 term(writer.connection, populated["id"]), term(writer.connection, "symbol"),
                 term(writer.connection, target), term(writer.connection, "example.com" if inside else "target.local"),
                 term(writer.connection, "source"), ref, "GET", 0),
            )
    writer.close()
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget())
    result = manifest_query(reader, "example.com", kind="symbol")
    assert result["results"] == [] and result["continuation_token"]
    result = GraphQuery(None, artifacts=reader).continue_query(result["continuation_token"])
    assert [row["id"] for row in result["results"]] == ["last"]
    assert not result["continuation_token"]
    reader.close()


def test_partial_enrichment_retains_only_fully_processed_candidates(populated, monkeypatch):
    writer = ArtifactStore("db")
    for index in range(3):
        writer.manifest.unit(populated["id"], f"unit-{index}")
    writer.close()
    reader = ArtifactStore("db", readonly=True, budget=QueryBudget())
    execute = reader.connection.execute
    calls = 0

    def interrupted(sql, parameters=()):
        nonlocal calls
        if sql.startswith("SELECT discovery,flow,materialization"):
            calls += 1
            if calls == 2:
                raise TimeoutError("deadline")
        return execute(sql, parameters)

    monkeypatch.setattr(reader.connection, "execute", interrupted)
    records, cursor = reader.manifest.page("example.com", kind="analysis_unit")
    assert len(records) == 1 and cursor == records[0]["manifest_id"]
    remaining, cursor = reader.manifest.page("example.com", kind="analysis_unit", after=cursor)
    assert len(remaining) == 4 and cursor is None
    reader.close()


async def test_metadata_timeout_preserves_element_records(populated, monkeypatch):
    from shyhurricane.mcp_server.graph_execution import execute_graph

    monkeypatch.setattr(GraphQuery, "omitted_regions", MagicMock(side_effect=TimeoutError("deadline")))
    result = await execute_graph(None, None, "elements", "example.com", artifact_db="db", kinds=["field"])
    assert len(result["results"]) == 12
    assert result["retrieval_truncated"] and "time_limit" in result["truncation_reasons"]
    assert "Deferred" in result["analysis_gaps"][-1]


async def test_tool_cancellation_waits_for_sqlite_worker_cleanup(populated, monkeypatch):
    import asyncio

    from shyhurricane.mcp_server.graph_execution import execute_graph

    started = threading.Event()
    finished = threading.Event()
    budgets = []

    def elements(service, scope):
        budgets.append(service.budget)
        service.artifacts.connection.set_trace_callback(lambda sql: started.set())
        try:
            service.artifacts.connection.execute(
                "WITH RECURSIVE numbers(n) AS (VALUES(0) UNION ALL "
                "SELECT n+1 FROM numbers WHERE n<1000000000) SELECT sum(n) FROM numbers"
            ).fetchall()
        finally:
            finished.set()

    monkeypatch.setattr(GraphQuery, "elements", elements)
    task = asyncio.create_task(execute_graph(None, None, "elements", "example.com", artifact_db="db"))
    assert await asyncio.to_thread(started.wait, 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finished.is_set() and not budgets[0].interrupts
    assert budgets[0].deadline - budgets[0].started == 120


@pytest.mark.parametrize("stage", ["coverage", "omitted"])
async def test_execution_metadata_deadline_does_not_discard_results(populated, monkeypatch, stage):
    from shyhurricane.mcp_server.graph_execution import execute_graph

    monkeypatch.setattr(GraphQuery, "elements", lambda *args: {"results": [{"id": "retained"}]})
    if stage == "coverage":
        monkeypatch.setattr("shyhurricane.graph.manifest.ManifestStore.coverage",
                            MagicMock(side_effect=TimeoutError("deadline")))
    else:
        monkeypatch.setattr(GraphQuery, "omitted_regions", MagicMock(side_effect=TimeoutError("deadline")))
    result = await execute_graph(None, None, "elements", "example.com", artifact_db="db")
    assert result["results"] == [{"id": "retained"}]
    assert result["analysis_gaps"] == ["Graph metadata exceeded the query budget"]
    assert result["truncation_reasons"] == ["time_limit"]
    if stage == "coverage":
        assert result["coverage"]["discovery"] == "unknown"


def test_continuation_lock_cancellation_and_serialization_rollback(tmp_path):
    from shyhurricane.graph.cursors import QueryCursors

    budget = QueryBudget()
    first = QueryCursors(tmp_path, budget)
    second = QueryCursors(tmp_path, budget)
    token = first.save({"operation": "fixture"})
    try:
        with first.locked(token):
            timer = threading.Timer(0.02, budget.cancel)
            timer.start()
            try:
                with pytest.raises(TimeoutError), second.locked(token):
                    pytest.fail("Contended lock acquired")
            finally:
                timer.join()
        with pytest.raises(TimeoutError):
            first.encode({"data": list(range(100))})
    finally:
        second.close()
        first.close()


def test_continuation_successor_and_replay_rollback_together(tmp_path):
    from shyhurricane.graph.cursors import QueryCursors

    cursors = QueryCursors(tmp_path)
    predecessor = cursors.save({"operation": "fixture"})
    try:
        with pytest.raises(OSError), cursors.transaction():
            successor = cursors.save({"operation": "next"})
            cursors.complete(predecessor, {"continuation_token": successor})
            raise OSError("checkpoint failed")
        assert cursors.response(predecessor) is None
        with pytest.raises(ValueError, match="unavailable"):
            cursors.load(successor)
        with cursors.transaction():
            successor = cursors.save({"operation": "next"})
            cursors.complete(predecessor, {"continuation_token": successor})
        assert cursors.response(predecessor) == {"continuation_token": successor}
        assert cursors.load(successor)[0] == {"operation": "next"}
    finally:
        cursors.close()


def test_budget_reserves_checkpoint_time_and_never_extends_deadline(monkeypatch):
    from shyhurricane.graph import budget as module

    clock = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    budget = QueryBudget()
    assert budget.remaining() == 115
    clock[0] = 126
    assert budget.remaining() == 0
    with budget.checkpoint():
        assert budget.remaining() == 4
        clock[0] = 130
        with pytest.raises(TimeoutError):
            budget.check()
    assert budget.deadline == 130


def test_continuation_does_not_hold_sqlite_read_lock_during_traversal(populated, monkeypatch):
    from shyhurricane.graph.cursors import QueryCursors

    artifacts = ArtifactStore("db", readonly=True, budget=QueryBudget())
    cursors = QueryCursors(artifacts.root)
    token = cursors.save({"operation": "paths", "parameters": {}, "search": {}})
    cursors.close()
    service = GraphQuery(None, artifacts=artifacts)

    def paths(**kwargs):
        other = QueryCursors(artifacts.root)
        try:
            independent = other.save({"operation": "independent"})
            assert other.load(independent)[0]["operation"] == "independent"
        finally:
            other.close()
        return {"results": [{"id": "completed"}]}

    monkeypatch.setattr(service, "paths", paths)
    try:
        result = service.continue_query(token)
        assert result == {"results": [{"id": "completed"}]}
        assert service.continue_query(token) == result
    finally:
        artifacts.close()
