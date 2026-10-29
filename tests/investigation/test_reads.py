"""Scalar filtering and bounded payload hydration preserve saved-result semantics."""

import json
import tracemalloc
from contextlib import closing

import pytest

from shyhurricane.investigation import storage
from shyhurricane.investigation.storage import CorrelationStore
from tests.investigation.test_storage import publish


@pytest.mark.parametrize("count", [10, 300])
def test_large_filtered_candidates_load_only_retained_payloads(monkeypatch, count):
    monkeypatch.setattr(storage, "MAX_TARGETS", 2)
    with closing(CorrelationStore("test")) as store:
        _, base = publish(store)
        base["witnesses"][0]["nodes"][0]["name"] = "x" * 50000
        with store.connection:
            for index in range(count):
                candidate = {**base, "id": f"candidate-{index:04}", "vulnerability_types": ["xss"]}
                store._write_target(candidate, json.dumps(candidate))
        statements = []
        store.connection.set_trace_callback(statements.append)
        tracemalloc.start()
        result = store.read("example.com", "xss")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert len(result["results"]) == 2 and result["retrieval_truncated"]
        assert [row["id"] for row in result["results"]] == ["candidate-0000", "candidate-0001"]
        loads = [sql for sql in statements if sql.startswith("SELECT id,payload FROM targets")]
        assert len(loads) == 1 and "candidate-0002" not in loads[0]
        # Generous structural bound: all 300 payloads would require at least 15 MiB.
        assert peak < 2_000_000
        assert store.read("example.com", "configuration")["results"] == []


def test_empty_scope_filtered_hypotheses_and_exact_cap_do_not_overreport(monkeypatch):
    monkeypatch.setattr(storage, "MAX_TARGETS", 1)
    with closing(CorrelationStore("test")) as store:
        _, result = publish(store)
        assert not store.read("example.com")["retrieval_truncated"]
        assert store.read("other.example.com")["results"] == []
        candidate = {**result, "id": "hypothesis", "hypothesis": True}
        with store.connection:
            store._write_target(candidate, json.dumps(candidate))
        assert not store.read("example.com", include_hypotheses=False)["retrieval_truncated"]
        assert store.read("example.com")["retrieval_truncated"]


def test_scope_bound_is_reported_without_loading_unrelated_payloads():
    with closing(CorrelationStore("test")) as store:
        with store.connection:
            store.connection.executemany(
                "INSERT INTO findings(id,target,host_key,metadata,conflicts,revision) VALUES (?,?,?,?,?,?)",
                (
                    (str(index), "https://example.com/other", "com.example", "{}", "[]", "revision")
                    for index in range(10001)
                ),
            )
        result = store.read("https://example.com/missing")
        assert result["results"] == [] and result["retrieval_truncated"]


def test_finding_context_coverage_and_title_revision():
    from shyhurricane.investigation.engine import correlate
    from tests.investigation.test_engine import Query
    with closing(CorrelationStore("test")) as store:
        metadata = {"source": "burp", "rule_id": "2097936"}
        store.submit("a", "https://example.com/app.js", metadata, title="DOM XSS")
        store.set_setting("graph_revision", 1)
        task = store.work(1)
        store.publish(task, correlate(task, Query(), 1), 1)
        result = store.read("example.com", "xss")
        assert result["findings"]["a"]["title"] == "DOM XSS"
        assert result["findings"]["a"]["metadata"] == metadata
        assert result["category_coverage"] == {"categorized": 1, "unknown": 0, "without_metadata": 0}
        assert store.read("other.example.com")["findings"] == {}
        assert store.read("example.com", "ssrf")["findings"] == {}
        store.submit("a", "https://example.com/app.js", metadata, title="Updated title")
        assert store.work(1)
        assert store.read("example.com")["results"][0]["stale"]


def test_category_coverage_includes_unknowns_before_filtering():
    with closing(CorrelationStore("test")) as store:
        publish(store)
        value = store.read("example.com", "xss")
        assert value["results"] == []
        assert value["category_coverage"] == {"categorized": 0, "unknown": 1, "without_metadata": 1}
        assert value["findings"] == {}


def test_read_deduplicates_identical_witnesses_and_calls():
    with closing(CorrelationStore("test")) as store:
        task, candidate = publish(store)
        candidate["witnesses"] *= 2
        candidate["follow_up"] *= 2
        with store.connection:
            store._write_target(candidate, json.dumps(candidate))
        result = store.read("example.com")["results"][0]
        assert len(result["witnesses"]) == len(candidate["witnesses"]) // 2
        calls = [json.dumps(call, sort_keys=True) for call in result["follow_up"]]
        assert len(calls) == len(set(calls))
