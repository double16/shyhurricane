"""Durability, atomic replacement, scope verification, and saved-result freshness."""

from contextlib import closing
from dataclasses import replace

from haystack import Document

from shyhurricane.investigation.engine import correlate
from shyhurricane.investigation.storage import (
    CorrelationStore,
    correlation_status,
    retry_correlations,
    submit_document,
)
from tests.investigation.test_engine import Query


def publish(store, finding_id="a", target="https://example.com/app.js", metadata=None, revision=1):
    store.submit(finding_id, target, metadata or {})
    store.set_setting("graph_revision", revision)
    task = store.work(revision)
    result = correlate(task, Query(), revision)
    assert store.publish(task, result, revision)
    return task, store.load_result(finding_id)


def test_obligations_survive_restart_and_publish_atomically():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "https://example.com/a", {})
        task = store.work(1)
        assert task["id"] == "a"
    with closing(CorrelationStore("test")) as store:
        assert store.work(1) == task
        candidate = correlate(task, Query(), 1)
        store.publish(task, candidate, 1)
        assert store.work(1) is None
        assert store.work(2)["id"] == "a"
        store.set_setting("graph_revision", 2)
        result = store.read("example.com")
        assert result["results"][0]["stale"]
        assert result["status"]["stale"] == 1
        assert store.status()["last_successful_refresh"]
        assert correlation_status("test")["stale"] == 1


def test_stale_metadata_is_not_activated_and_last_result_retained():
    with closing(CorrelationStore("test")) as store:
        task, candidate = publish(store)
        store.submit("a", task["target"], {"severity": "high"})
        assert not store.publish(task, candidate, 1)
        assert store.read("example.com")["results"][0]["stale"]
        new = store.work(1)
        replacement = correlate(new, Query(), 1)
        store.publish(new, replacement, 1)
        assert not store.read("example.com")["results"][0]["stale"]
        assert store.read("example.com")["results"][0]["priority"] > candidate["priority"]
        store.submit("a", task["target"], {"severity": "high"})
        assert store.work(1) is None
        assert not store.publish({**task, "id": "missing"}, candidate, 1)


def test_permanent_failure_retry_and_transient_backoff():
    assert retry_correlations("test") == 0
    assert correlation_status("test")["completed"] == 0
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {})
        task = store.work(1)
        store.failed(task, ValueError("invalid"), transient=False)
        assert store.work(1) is None
        assert store.status()["failed"] == 1
        assert retry_correlations("test") == 1
        assert store.work(1)["id"] == "a"
        task = store.work(1)
        store.failed(task, TimeoutError(), transient=True)
        assert store.work(1) is None
        assert store.attempts("a") == 1
        store.connection.execute("UPDATE jobs SET due=0")
        store.connection.commit()
        assert store.work(1)


def test_neighbors_are_bounded_indexed_and_false_positives_remove_results():
    with closing(CorrelationStore("test")) as store:
        task, result = publish(store)
        neighbors, limited = store.neighbors(result["association_keys"])
        assert neighbors == [result] and not limited
        assert store.neighbors(result["association_keys"], limit=0) == ([], True)
        # A checkpoint with no payload is safely ignored.
        store.connection.execute("UPDATE findings SET result=NULL")
        store.connection.commit()
        assert store.neighbors(result["association_keys"])[0] == []
        store.submit("a", task["target"], {"verification_status": "false_positive"})
        task = store.work(1)
        store.publish(task, correlate(task, Query(), 1), 1)
        assert store.read("example.com")["results"] == []


def test_scope_category_and_hypothesis_filters_and_cross_scope_dependencies():
    from shyhurricane.investigation.rules import pair_candidate

    with closing(CorrelationStore("test")) as store:
        task, left = publish(store, "a", "https://example.com:8443/admin", {"vulnerability_types": ["xss"]})
        _, right = publish(store, "b", "https://api.example.com/user", {"vulnerability_types": ["configuration"]})
        chain = pair_candidate(left, right, "protection_gap", [])
        derive_job = store._select_job(("derive",))
        store.publish_derived(derive_job, [chain], dependency=left)
        assert len(store.read("example.com")["results"]) == 3
        assert len(store.read("example.com", include_hypotheses=False)["results"]) == 2
        assert len(store.read("example.com", vulnerability_type="xss")["results"]) == 2
        assert len(store.read("https://example.com:8443/admin")["results"]) == 1
        assert store.read("example.com:443")["results"][0]["affected_urls"] == ["https://api.example.com/user"]
        assert store.read("notexample.com")["results"] == []
        assert store.read("https://api.example.com/missing")["results"] == []
        publish(store, "c", "example.com")
        assert len(store.read("https://example.com:8443/admin")["results"]) == 1
        store.set_setting("reconcile_complete", True)
        assert store.read("example.com")["analysis_gaps"] == []


def test_read_truncation_and_stable_order(monkeypatch):
    import shyhurricane.investigation.storage as storage

    monkeypatch.setattr(storage, "MAX_TARGETS", 1)
    with closing(CorrelationStore("test")) as store:
        publish(store, "a")
        publish(store, "b")
        result = store.read("example.com")
        assert result["retrieval_truncated"]
        assert result["truncation_reasons"] == ["result_limit"]
        assert len(result["results"]) == 1
        assert "metadata" not in result["results"][0]


def test_document_handoff_uses_target_and_metadata():
    doc = Document(
        id="a", content="finding", meta={"url": "https://example.com/a", "finding_metadata": {"severity": "high"}}
    )
    submit_document("test", doc)
    submit_document("test", replace(doc, id="b", meta={"netloc": "example.com:8443"}))
    submit_document("test", replace(doc, id="c", meta={"host": "example.com"}))
    with closing(CorrelationStore("test")) as store:
        assert store.work(1)["metadata"] == {"severity": "high"}
        assert store.status()["pending"] == 3


def test_ranking_precedes_result_cap_and_scope_strips_unrelated_context(monkeypatch):
    import shyhurricane.investigation.storage as storage

    monkeypatch.setattr(storage, "MAX_TARGETS", 1)
    with closing(CorrelationStore("test")) as store:
        publish(store, "a", metadata={"severity": "low"})
        _, high = publish(store, "z", metadata={"severity": "critical"})
        result = store.read("https://example.com/app.js")
        assert result["results"][0]["finding_ids"] == ["z"]
        assert result["results"][0]["scope_limited"]
        assert result["results"][0]["context_urls"] == ["https://example.com/app.js"]
        assert all(
            call["arguments"].get("scope", "https://example.com/app.js") == "https://example.com/app.js"
            for call in result["results"][0]["follow_up"]
        )


def test_neighbor_key_budget_is_reported_and_failed_results_keep_status():
    with closing(CorrelationStore("test")) as store:
        task, _ = publish(store)
        assert store.neighbors([str(index) for index in range(101)])[1]
        with store.connection:
            store.enqueue("correlate", task["id"])
        store.failed(store.work(1), ValueError(), transient=False)
        assert store.read("example.com")["results"][0]["materialization_status"] == "failed"


def test_reconciliation_cannot_overwrite_a_newer_enrichment():
    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {"severity": "critical"}, source_revision=2)
        store.submit("a", "example.com", {"severity": "low"}, source_revision=1)
        assert store.work(0)["metadata"] == {"severity": "critical"}
        store.submit("a", "example.com", {"severity": "high"}, source_revision=3)
        assert store.work(0)["metadata"] == {"severity": "high"}


def test_bare_ipv6_submission_and_correlation():
    with closing(CorrelationStore("test")) as store:
        store.submit("ipv6", "2001:db8::1", {})
        task = store.work(1)
        result = correlate(task, Query(), 1)
        assert result["anchor"] == "host"
        store.publish(task, result, 1)
        assert store.read("[2001:db8::1]")["results"]


def test_publication_starts_write_transaction_before_revision_check():
    import sqlite3

    with closing(CorrelationStore("test")) as store:
        store.submit("a", "example.com", {})
        task = store.work(1)
        statements = []
        store.connection.set_trace_callback(statements.append)
        store.publish(task, correlate(task, Query(), 1), 1)
        begin = next(i for i, sql in enumerate(statements) if sql == "BEGIN IMMEDIATE")
        check = next(i for i, sql in enumerate(statements) if sql.startswith("SELECT revision"))
        assert begin < check
        assert not store.connection.in_transaction
        assert isinstance(store.connection, sqlite3.Connection)


def test_second_connection_cannot_enrich_between_revision_check_and_commit():
    import sqlite3

    import pytest

    with closing(CorrelationStore("test")) as store, closing(CorrelationStore("test")) as writer:
        store.submit("a", "example.com", {})
        task = store.work(1)
        writer.connection.execute("PRAGMA busy_timeout=0")
        checked = []

        def during_publication(sql):
            if sql.startswith("SELECT revision FROM findings"):
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    writer.submit("a", "example.com", {"severity": "high"})
                checked.append(True)

        store.connection.set_trace_callback(during_publication)
        assert store.publish(task, correlate(task, Query(), 1), 1)
        assert checked
        store.connection.set_trace_callback(None)
        writer.submit("a", "example.com", {"severity": "high"})
        new = store.work(1)
        assert new["generation"] > task["generation"]
        assert new["metadata"] == {"severity": "high"}
        store.failed(task, ValueError(), transient=False)
        assert store.work(1) == new
