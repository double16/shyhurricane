"""Passive correlation must distinguish association from supported flow."""

import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.model import identity
from shyhurricane.investigation.engine import (
    RevisionQuery,
    artifact_hash_verifier,
    correlate,
    correlation_query,
    operation_matches,
)

URL = "https://example.com/app.js"
PAGE = "https://example.com/page"


def job(metadata=None, target=URL, finding_id="finding"):
    metadata = metadata or {}
    return {
        "id": finding_id,
        "target": target,
        "metadata": metadata,
        "conflicts": [],
        "revision": identity(metadata, []),
    }


def node(key, role="", **extra):
    return {
        "id": key,
        "url": URL,
        "kind": "result",
        "role": role,
        "source_path": URL,
        "location": "2:0",
        "capture_id": "capture",
        **extra,
    }


def flow(nodes=None, kind="FLOWS_TO"):
    nodes = nodes or [node("input", "source"), node("sink", "sink")]
    return {
        "nodes": nodes,
        "steps": [
            {"id": "step", "source": nodes[0]["id"], "target": nodes[-1]["id"], "kind": kind, "evidence_id": "proof"}
        ],
    }


class Query:
    def __init__(self, operations=(), paths=None, resources=None, truncated=False):
        self.operations = list(operations)
        self.paths_result = paths
        self.resources = resources if resources is not None else [{"id": "resource", "url": URL, "method": "GET"}]
        self.calls = []
        self.truncated = truncated

    def wrap(self, values):
        return {
            "results": values,
            "retrieval_truncated": self.truncated,
            "truncation_reasons": ["result_limit"],
            "analysis_gaps": [],
        }

    def endpoints(self, *args, **kwargs):
        self.calls.append(("endpoints", args, kwargs))
        return self.wrap(self.resources)

    def elements(self, *args, **kwargs):
        return self.wrap(self.operations)

    def paths(self, *args, **kwargs):
        self.calls.append(("paths", args, kwargs))
        if kwargs.get("kinds") == ["RESPONSE_FROM"]:
            return self.wrap([])
        if callable(self.paths_result):
            return self.wrap(self.paths_result(args, kwargs))
        if kwargs.get("mode") == "relationships":
            return self.wrap(
                [
                    {
                        "nodes": [
                            {"id": "page", "kind": "resource", "url": PAGE},
                            {"id": "script", "kind": "resource", "url": URL},
                        ],
                        "steps": [{"kind": "LOADS", "source": "page", "target": "script", "evidence_id": "load"}],
                    }
                ]
            )
        return self.wrap(self.paths_result if self.paths_result is not None else [flow()])


def test_script_consumers_are_separate_from_flow_and_have_evidence():
    result = correlate(job({"cwe_ids": ["CWE-79"], "severity": "high"}), Query(), 4)
    assert result["context_urls"] == [URL, PAGE]
    assert result["anchor"] == "url"
    assert result["connectivity"] == "contextual_flow"
    assert result["evidence_ids"] == ["load", "proof"]
    assert result["vulnerability_types"] == ["xss"]
    assert {w["relation"] for w in result["witnesses"]} == {"consumer", "flow"}
    assert result["follow_up"][0]["arguments"]["url"] == URL


def test_host_findings_and_false_positives_do_not_traverse():
    query = Query()
    result = correlate(job(target="example.com"), query, 0)
    assert result["anchor"] == "host" and result["priority"] <= 20
    assert query.calls == []
    assert correlate(job({"verification_status": "false_positive"}), query, 0)["excluded"]


def location(**extra):
    return {
        "code_location": {"source_path": "source.js", "coordinate_space": "delivered", "start_line": 2},
        "capture_id": "capture",
        **extra,
    }


def test_operation_identity_and_flow():
    operation = node("sink", "sink")
    result = correlate(job(location(affected_method="GET")), Query([operation]), 3)
    assert result["anchor"] == "operation"
    assert result["operation_ids"] == ["sink"]
    assert result["connectivity"] == "anchored_flow"
    assert result["score_contributions"]["anchor"] == 20


@pytest.mark.parametrize(
    "metadata,changed,expected",
    [
        (location(), {}, True),
        (location(capture_id="wrong"), {}, False),
        (location(capture_id=None), {}, False),
        (location(content_sha256="a" * 64), {}, True),
        (location(), {"location": "garbage"}, False),
        (location(), {"location": "3:0"}, False),
        (location(), {"source_path": "different.js"}, False),
        ({"code_location": {"coordinate_space": "unknown"}}, {}, False),
        ({"code_location": {"source_path": URL, "coordinate_space": "delivered"}}, {}, False),
        ({"code_location": {"source_path": "source.js", "start_line": 2, "coordinate_space": "recovered"}}, {}, False),
    ],
)
def test_code_location_matching(metadata, changed, expected):
    assert operation_matches(node("op", **changed), metadata, URL, lambda *args: True) == expected


def test_code_coordinate_spaces_columns_and_hash():
    metadata = location(capture_id=None, content_sha256="a" * 64)
    assert operation_matches(node("op"), metadata, URL, lambda *args: True)
    assert not operation_matches(node("op"), metadata, URL, lambda *args: False)
    metadata["code_location"].update(start_column=2)
    assert not operation_matches(node("op"), metadata, URL, lambda *args: True)
    metadata["code_location"].update(source_path="original.ts", coordinate_space="recovered", start_column=1)
    assert operation_matches(node("op", source_path="original.ts"), metadata, URL, lambda *args: True)


def test_missing_resources_and_method_ambiguity_and_conflicts():
    result = correlate(job(location()), Query(resources=[]), 1)
    assert result["anchor"] == "host"
    assert any("no resource" in gap for gap in result["analysis_gaps"])
    result = correlate(job(), Query(resources=[{"id": "get", "method": "GET"}, {"id": "post", "method": "POST"}]), 1)
    assert any("multiple resource methods" in gap for gap in result["analysis_gaps"])
    value = job(location(affected_method="GET"))
    value["conflicts"] = [{"field": "affected_method", "retained": "GET", "submitted": "POST"}]
    result = correlate(value, Query([node("op")]), 1)
    assert result["anchor"] == "url"
    assert result["score_contributions"]["metadata_conflict"] == -10
    assert correlate(job({"affected_method": "GET"}), Query(), 1)["anchor"] == "method"


def test_truncation_summary_and_no_path_are_reported():
    result = correlate(job(), Query(paths=[], truncated=True), 1)
    assert result["incomplete_path"] and result["contexts_limited"]
    assert any("No relevant" in gap for gap in result["analysis_gaps"])
    result = correlate(job(), Query(paths=[flow(kind="SUMMARIZED_FLOW")]), 1)
    assert result["score_contributions"]["incomplete_path"] == -10


def test_witness_and_seed_budgets():
    result = correlate(
        job({"vulnerability_types": ["authentication"]}),
        Query(resources=[{"id": str(index), "method": "GET"} for index in range(21)], paths=[flow()] * 101),
        1,
    )
    assert result["contexts_limited"]
    assert any("Witness retention" in gap for gap in result["analysis_gaps"])
    assert any("20 methods" in gap for gap in result["analysis_gaps"])
    assert any(w["relation"] == "journey" for w in result["witnesses"])


def test_operation_join_bounded_and_context_compatible():
    operation = node("operation")

    def paths(args, kwargs):
        if kwargs.get("mode") != "flow":
            return []
        if args[1] == "resource":
            return []
        if kwargs.get("direction") == "backward":
            return [flow([operation, node("source", "source")])] * 21
        return [flow([operation, node("sink", "sink")])] * 21

    result = correlate(job(location()), Query([operation] * 11, paths=paths), 2)
    assert result["connectivity"] == "anchored_flow"
    assert result["contexts_limited"]
    assert all(w["nodes"][0]["role"] == "source" for w in result["witnesses"])


def test_operation_source_and_cyclic_or_conflicting_joins():
    operation = node("source", "source")
    result = correlate(job(location()), Query([operation]), 2)
    assert result["anchor"] == "operation"

    def paths(args, kwargs):
        if args[1] != "operation" or kwargs.get("mode") != "flow":
            return []
        before = kwargs.get("direction") == "backward"
        witness = flow([node("operation"), node("shared", "source" if before else "sink")])
        return [witness]

    result = correlate(job(location()), Query([node("operation")], paths=paths), 1)
    assert result["connectivity"] == "association"

    def incompatible(args, kwargs):
        before = kwargs.get("direction") == "backward"
        witness = flow([node("operation"), node("source" if before else "sink", "source" if before else "sink")])
        witness["steps"][0]["context_capture_id"] = "one" if before else "two"
        return [witness] if args[1] == "operation" else []

    result = correlate(job(location()), Query([node("operation")], paths=incompatible), 1)
    assert result["connectivity"] == "association"


def test_hash_verification_reads_retained_capture_once():
    artifacts = SimpleNamespace(connection=Mock(), read=Mock(return_value={"data": {"response_body": "code"}}))
    artifacts.connection.execute.return_value.fetchone.return_value = ("artifact",)
    verify = artifact_hash_verifier(artifacts)
    digest = hashlib.sha256(b"code").hexdigest()
    assert verify(node("op"), digest)
    assert verify(node("op"), digest)
    assert artifacts.read.call_count == 1
    assert not verify(node("op", capture_id=None), digest)
    assert not verify(node("op", source_path="recovered.ts"), digest)
    artifacts.connection.execute.return_value.fetchone.return_value = None
    assert not verify(node("other", capture_id="missing"), digest)


def test_revision_query_pins_all_operations():
    store = Mock()
    store.read.return_value = [{"ready": True}]
    query = RevisionQuery(store, 9, QueryBudget())
    assert query.read("/* traversal:revision */ ignored") == [{"revision": 9}]
    assert query.read("other") == [{"ready": True}]
    with pytest.raises(TimeoutError):
        query.snapshot("example.com")
    assert correlation_query(store, 1).revision == 1


def test_compact_witness_omits_unbounded_context_arrays_but_keeps_proofs():
    from shyhurricane.investigation.engine import compact_witness

    witness = flow(
        [
            node("input", "source", context_urls=[f"https://example.com/{index}" for index in range(12000)]),
            node("sink", "sink"),
        ]
    )
    witness["steps"][0]["context_capture_id"] = "document"
    compact = compact_witness(witness)
    assert len(compact["nodes"][0]["context_urls"]) == 3
    assert compact["nodes"][0]["capture_id"] == "capture"
    assert compact["steps"][0]["evidence_id"] == "proof"
    assert compact["steps"][0]["context_capture_id"] == "document"
    assert compact["possible_path"]
