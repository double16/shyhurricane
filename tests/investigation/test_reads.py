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
