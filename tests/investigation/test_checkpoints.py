"""Correlation slices retain evidence without publishing unfinished results."""

from contextlib import closing
from unittest.mock import Mock

import pytest
from neo4j.exceptions import Neo4jError

from shyhurricane.graph.budget import QueryBudget
from shyhurricane.investigation import checkpoints
from shyhurricane.investigation.checkpoints import Checkpoint, CheckpointQuery, CheckpointYield
from shyhurricane.investigation.engine import RevisionQuery, correlate
from shyhurricane.investigation.storage import CorrelationStore
from tests.investigation.test_engine import Query


def graph():
    return Mock(read=Mock(side_effect=lambda statement, **kw: [{"id": kw["id"]}] if "RETURN p.id" in statement else []))


def start(store, database=None, revision=1):
    store.submit("finding", "https://example.com/app.js", {})
    job = store.next_job(revision)
    return Checkpoint(store, database or graph(), job, revision)


def wrapped(checkpoint, query=None):
    query = query or Query()
    query.read = Mock(return_value=[{"value": 1}])
    return CheckpointQuery(query, checkpoint)


def test_read_and_operation_survive_reopen_and_publish_atomically():
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)
        assert query.read("page") == [{"value": 1}]
        query.read("page")
        query.original_read.assert_called_once()
        assert query.original_read.call_args.kwargs["timeout"] == 5
        result = query.endpoints("example.com")
        checkpoint.defer()
        assert store.status()["pending"] == 1
        assert store.status()["last_successful_refresh"] is None
        assert store.status()["refresh_progress"][0]["stage"] == "endpoints"
        job = checkpoint.job
    with closing(CorrelationStore("test")) as store:
        checkpoint = Checkpoint(store, graph(), job, 1)
        resumed = wrapped(checkpoint)
        assert resumed.read("page") == [{"value": 1}]
        resumed.original_read.assert_not_called()
        assert resumed.endpoints("example.com") == result
        complete = correlate(job, Query(), 1)
        assert store.publish(job, complete, 1)
        assert store.connection.execute("SELECT count(*) FROM checkpoint_pages").fetchone()[0] == 0
        assert store.status()["refresh_progress"] == []
        assert not store.publish(job, complete, 1)


@pytest.mark.parametrize("change", ["generation", "revision", "expiry"])
def test_obsolete_checkpoints_are_discarded(change, monkeypatch):
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        checkpoint.save("old", [1])
        job = dict(checkpoint.job)
        revision = 1
        if change == "generation":
            store.submit("finding", "https://example.com/app.js", {"severity": "high"})
            job = store.next_job(1)
        elif change == "revision":
            revision = 2
        else:
            monkeypatch.setattr(checkpoints.time, "time", lambda: 10**12)
        fresh = Checkpoint(store, graph(), job, revision)
        assert fresh.load("old") is None


def test_generation_guard_caps_backoff_and_fairness(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        checkpoint.defer()
        assert store.attempts("finding") == 1
        checkpoint.save("empty", [])
        checkpoint.defer()
        assert store.attempts("finding") == 0
        store.submit("other", "https://example.com/other", {})
        assert store.next_job(1) is None
        monkeypatch.setattr(checkpoints, "MAX_JOB_BYTES", 1)
        with pytest.raises(checkpoints.CheckpointCapacityError, match="storage"):
            checkpoint.save("big", [1])
        monkeypatch.setattr(checkpoints, "MAX_JOB_BYTES", 100)
        monkeypatch.setattr(checkpoints, "MAX_TOTAL_BYTES", 1)
        with pytest.raises(checkpoints.CheckpointCapacityError, match="storage"):
            checkpoint.save("big", [1])
        store.submit("finding", "https://example.com/app.js", {"severity": "high"})
        with pytest.raises(CheckpointYield, match="generation"):
            checkpoint.save("stale", [])


def test_pin_confirmation_and_release():
    with closing(CorrelationStore("test")) as store:
        database = graph()
        checkpoint = start(store, database)
        checkpoint.release()
        assert "DELETE p" in database.read.call_args.args[0]
        database.read.side_effect = None
        database.read.return_value = []
        with pytest.raises(TimeoutError, match="pin"):
            checkpoint.renew()


def test_path_frontier_and_witnesses_resume_without_partial_publication():
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)

        def first(*args, **kwargs):
            query.query.path_checkpoint({"pending": ["next"]}, {
                "results": [{"id": "first"}], "truncation_reasons": ["time_limit"],
            })

        query.query.paths = first
        with pytest.raises(CheckpointYield):
            query.paths("example.com", "start")
        resumed = wrapped(Checkpoint(store, graph(), checkpoint.job, 1))
        resumed.query.paths = Mock(return_value={"results": [{"id": "second"}]})
        result = resumed.paths("example.com", "start")
        assert result["results"] == [{"id": "first"}, {"id": "second"}]
        assert resumed.query.paths.call_args.kwargs["_resume"]["pending"] == ["next"]
        assert store.status()["last_successful_refresh"] is None


@pytest.mark.parametrize("reason,error", [("time_limit", CheckpointYield), ("generation_unavailable", TimeoutError)])
def test_incomplete_operations_are_never_cached(reason, error):
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)
        query.query.elements = Mock(return_value={"results": [], "truncation_reasons": [reason]})
        with pytest.raises(error):
            query.elements("example.com")
        assert checkpoint.load("result:" + query.operation_key) is None
        query.path_checkpoint({}, {"truncation_reasons": ["result_limit"]})
        query.query.location_elements = Mock(return_value={"results": []})
        assert query.location_elements("example.com", "url", {}) == {"results": []}


def test_focused_anchor_lookup_does_not_expand_contexts(monkeypatch):
    reader = Mock()
    reader.nodes = {"resource": {"id": "resource", "url": "https://example.com/a", "method": "GET"}}
    reader.metadata = {}
    monkeypatch.setattr("shyhurricane.graph.traversal.TraversalSnapshot", lambda *args, **kw: reader)
    query = RevisionQuery(Mock(), 1, QueryBudget())
    result = query.endpoints("example.com", url="https://example.com/a", method="GET")
    assert result["results"][0]["id"] == "resource"
    reader.contextual.assert_not_called()
    reader.load.assert_not_called()
    reader.indexed.return_value = False
    with pytest.raises(TimeoutError):
        query.endpoints("example.com")


@pytest.mark.parametrize("version", [4, 5])
def test_old_checkpoint_schema_requires_rebuild(version):
    with closing(CorrelationStore("test")) as store:
        store.submit("finding", "https://example.com/a", {})
        store.connection.execute(f"PRAGMA user_version={version}")
        store.connection.commit()
    with pytest.raises(ValueError, match="rebuild"):
        CorrelationStore("test")


def test_identical_checkpoints_are_not_progress_and_reset_is_generation_guarded():
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        checkpoint.save("page", [1])
        checkpoint.progressed = False
        checkpoint.save("page", [1])
        assert not checkpoint.progressed
        checkpoint.reset()
        assert checkpoint.load("page") is None
        checkpoint = Checkpoint(store, graph(), checkpoint.job, 1)
        checkpoint.save("page", [2])
        store.submit("finding", "https://example.com/app.js", {"severity": "high"})
        checkpoint.reset()
        assert checkpoint.load("page") == [2]
        with pytest.raises(CheckpointYield):
            checkpoint.enter("stale")
        with pytest.raises(CheckpointYield):
            Checkpoint(store, graph(), checkpoint.job, 1)
        checkpoint.prune("stale")


def test_completed_stages_discard_reconstruction_pages():
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)
        query.query.endpoints = lambda *args, **kw: {"results": query.query.read("page")}
        expected = query.endpoints("example.com")
        assert query.endpoints("example.com") == expected
        keys = [row[0] for row in store.connection.execute("SELECT key FROM checkpoint_pages")]
        assert keys == ["result:" + query.operation_key]


def test_timeout_preserves_completed_reads_and_defers_without_publication(monkeypatch):
    from shyhurricane.investigation import worker

    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)
        query.read("good-page")
        query.query.budget.deadline = 0
        with pytest.raises(TimeoutError):
            query.read("good-page")
        # Use a fresh fake query, as the old query's read is bound to its previous slice.
        fresh = Query()
        fresh.elements = Mock(side_effect=TimeoutError())
        monkeypatch.setattr(worker, "correlation_query", lambda *args: fresh)
        assert worker.materialize_one(store, graph(), Mock(), 1)
        assert store.status()["completed"] == 0
        assert store.status()["last_successful_refresh"] is None
        assert store.status()["pending"] == 1
        assert store.status()["refresh_progress"][0]["stage"] == "elements"


@pytest.mark.parametrize("code", [
    "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration",
    "Neo.TransientError.General.MemoryPoolOutOfMemoryError",
])
def test_reduced_page_sizes_survive_worker_restart(code):
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        query = wrapped(checkpoint)
        query.original_read.side_effect = Neo4jError._hydrate_neo4j(code=code, message="slow page")
        with pytest.raises(Neo4jError):
            query.read("page", limit=500)
        fresh = wrapped(Checkpoint(store, graph(), checkpoint.job, 1))
        fresh.read("page", limit=500)
        assert fresh.original_read.call_args.kwargs["limit"] == 250
        fresh.read("page", limit=500)
        fresh.original_read.assert_called_once()


def test_non_budget_database_errors_do_not_reduce_pages():
    with closing(CorrelationStore("test")) as store:
        query = wrapped(start(store))
        query.original_read.side_effect = Neo4jError._hydrate_neo4j(
            code="Neo.ClientError.Statement.SyntaxError", message="invalid statement",
        )
        with pytest.raises(Neo4jError):
            query.read("page", limit=500)
        with pytest.raises(Neo4jError):
            query.read("page", limit=1)


def test_unavailable_generation_restarts_and_release_failure_does_not_undo_publish(monkeypatch):
    from shyhurricane.investigation import worker

    with closing(CorrelationStore("test")) as store:
        start(store)
        query = Query()
        query.elements = Mock(return_value={"results": [], "truncation_reasons": ["generation_unavailable"]})
        monkeypatch.setattr(worker, "correlation_query", lambda *args: query)
        worker.materialize_one(store, graph(), Mock(), 1)
        assert store.status()["completed"] == 0
        assert store.status()["refresh_progress"] == []
        store.connection.execute("UPDATE jobs SET due=0")
        store.connection.commit()
        monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
        monkeypatch.setattr(Checkpoint, "release", Mock(side_effect=OSError("offline")))
        worker.materialize_one(store, graph(), Mock(), 1)
        assert store.status()["completed"] == 1


def test_recovery_bounds_admission_and_releases_excess():
    with closing(CorrelationStore("test")) as store:
        first = start(store)
        first.save("page", [1])
        store.submit("other", "https://example.com/other", {})
        job = store._select_job(("correlate",), finding_id="other")
        second = Checkpoint(store, graph(), job, 1)
        second.save("page", [2])
        database = graph()
        checkpoints.recover_checkpoints(store, database, 1)
        assert store.connection.execute("SELECT finding_id FROM checkpoints").fetchall() == [("other",)]
        assert first.load("page") is None
        assert second.load("page") == [2]
        assert store.next_job(1)["id"] == "other"
        database.read.assert_called_once()
        checkpoints.recover_checkpoints(store, database, 2)
        assert store.connection.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0


def test_atomic_compaction_makes_room(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        checkpoint.save("read:op:page", "abcdef")
        monkeypatch.setattr(checkpoints, "MAX_JOB_BYTES", 10)
        checkpoint.save("search:op", "abcdefg")
        assert checkpoint.load("read:op:page") is None
        assert checkpoint.load("search:op") == "abcdefg"
        with pytest.raises(checkpoints.CheckpointCapacityError):
            checkpoint.save("result:op", "too large to save")
        assert checkpoint.load("search:op") == "abcdefg"


def test_capacity_failure_releases_admission(monkeypatch):
    from shyhurricane.investigation import worker

    with closing(CorrelationStore("test")) as store:
        store.submit("finding", "https://example.com/app.js", {})
        monkeypatch.setattr(checkpoints, "MAX_JOB_BYTES", 1)
        monkeypatch.setattr(worker, "correlate", lambda job, query, *args, **kwargs: query.read("page"))
        monkeypatch.setattr(worker, "correlation_query", lambda *args: wrapped_query())
        assert worker.materialize_one(store, graph(), Mock(), 1)
        assert store.status()["checkpoint_storage"]["capacity_failures"] == 1
        assert store.status()["checkpoint_storage"]["active_finding"] is None
        assert store.status()["last_successful_refresh"] is None


def wrapped_query():
    query = Query()
    query.read = Mock(return_value=[{"value": 1}])
    return query


def test_transactional_byte_accounting():
    with closing(CorrelationStore("test")) as store:
        checkpoint = start(store)
        for value in ([1], [1, 2, 3], []):
            checkpoint.save("page", value)
            actual = store.connection.execute("SELECT sum(size) FROM checkpoint_pages").fetchone()[0]
            assert store.status()["checkpoint_storage"]["used_bytes"] == actual
            assert store.connection.execute("SELECT bytes FROM checkpoint_usage").fetchone()[0] == actual
        with pytest.raises(RuntimeError), store.connection:
            store.connection.execute("DELETE FROM checkpoint_pages")
            raise RuntimeError()
        assert store.status()["checkpoint_storage"]["used_bytes"] == actual
        checkpoint.reset()
        assert store.status()["checkpoint_storage"]["used_bytes"] == 0
        assert store.connection.execute("SELECT count(*) FROM checkpoint_usage").fetchone()[0] == 0
