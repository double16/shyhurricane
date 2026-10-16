"""Frontier loading, shared budgets, and parity against a complete small graph."""

from collections import defaultdict, deque

import pytest
from neo4j.exceptions import Neo4jError
from test_query import Store

from shyhurricane.graph.discovery import ResourceDiscovery
from shyhurricane.graph.model import FLOW_KINDS, JOURNEY_KINDS, Projection
from shyhurricane.graph.query import GraphQuery
from shyhurricane.graph.traversal import TraversalSnapshot


@pytest.fixture
def application(event):
    graph = Projection(event())
    page = graph.resource(graph.url)
    script = graph.resource("https://example.com/app.js")
    outside = graph.resource("https://other.test/")
    source = graph.node("source", "input", role="source", context_urls=[graph.url])
    middle = graph.node("symbol", "middle")
    sink = graph.node("sink", "eval", role="sink", context_urls=[graph.url])
    for a, b, kind in (
        (page, script, "LOADS"),
        (script, source, "CONTAINS"),
        (script, sink, "CONTAINS"),
        (source, middle, "FLOWS_TO"),
        (middle, sink, "CALL_ARGUMENT"),
        (middle, source, "FLOWS_TO"),
        (page, outside, "NAVIGATES_TO"),
    ):
        graph.fact(a, b, kind, "test")
    return graph, page, source, sink, outside


def signatures(result):
    return [
        (tuple(node["id"] for node in path["nodes"]), tuple(step["id"] for step in path["steps"]))
        for path in result["results"]
    ]


def reference_paths(service, start, end, mode, direction, depth):
    """Small complete-snapshot oracle: independent of database frontier loading."""
    nodes, edges, _ = service.snapshot("example.com")
    discovery = ResourceDiscovery(nodes, edges)
    backward = direction == "backward"
    starts = discovery.select(start, ("sink" if backward else "source") if mode == "flow" else None)
    ends = set(discovery.select(end, ("source" if backward else "sink") if mode == "flow" else None)) if end else set()
    allowed = FLOW_KINDS if mode == "flow" else JOURNEY_KINDS if mode == "journey" else None
    adjacent = defaultdict(list)
    for edge in sorted(edges, key=lambda edge: edge["id"]):
        if allowed is None or edge["kind"] in allowed:
            adjacent[edge["target"] if backward else edge["source"]].append(edge)
    queue = deque(([key], []) for key in starts)
    results = []
    while queue:
        path, steps = queue.popleft()
        current = path[-1]
        if steps and (
            current in ends
            if end
            else mode != "flow" or nodes[current].get("role") == ("source" if backward else "sink")
        ):
            results.append((tuple(path), tuple(steps)))
            if end:
                continue
        if len(steps) >= depth or not nodes[current]["url"].startswith("https://example.com/"):
            continue
        for edge in adjacent[current]:
            target = edge["source"] if backward else edge["target"]
            if target not in path:
                queue.append(([*path, target], [*steps, edge["id"]]))
    return results


@pytest.mark.parametrize("mode", ["relationships", "flow", "journey"])
@pytest.mark.parametrize("direction", ["forward", "backward"])
@pytest.mark.parametrize("detail", ["compact", "full"])
def test_frontier_matches_complete_snapshot_for_small_graphs(application, mode, direction, detail):
    graph, page, source, sink, outside = application
    service = GraphQuery(Store(graph))
    start = sink if direction == "backward" and mode == "flow" else page if mode != "flow" else source
    end = outside if mode == "journey" else None
    expected = reference_paths(service, start, end, mode, direction, 3)
    result = service.paths("example.com", start, end=end, mode=mode, direction=direction, max_depth=3, detail=detail)
    assert signatures(result) == expected


def test_resource_flow_associations_are_not_path_evidence(application, monkeypatch):
    graph, page, source, sink, _ = application
    service = GraphQuery(Store(graph))
    monkeypatch.setattr(service, "snapshot", lambda *a, **kw: pytest.fail("No whole-scope snapshot allowed"))
    result = service.paths("example.com", graph.url, end=graph.url, mode="flow")
    assert result["resolved_start_ids"] == [source] and result["resolved_end_ids"] == [sink]
    assert all(step["kind"] in FLOW_KINDS for path in result["results"] for step in path["steps"])
    assert all(node["id"] != page for path in result["results"] for node in path["nodes"])


def test_frontier_adjacency_cache_and_deadline_preserve_complete_paths(application, monkeypatch):
    graph, _, source, sink, _ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    reader.select(source, None)
    reader.expand([source], "forward", FLOW_KINDS)
    old = reader.read
    calls = []

    def record(statement, **parameters):
        calls.append(statement)
        return old(statement, **parameters)

    reader.read = record
    reader.expand([source], "forward", FLOW_KINDS)
    assert not calls
    reader.started -= 121
    assert not reader.read("expired")
    assert reader.stopped
    reader.expand([source], "forward", FLOW_KINDS)
    assert reader.adjacent[source]

    # The next frontier deadline must not discard a fully hydrated pending destination.
    from shyhurricane.graph import traversal

    original = traversal.TraversalSnapshot.expand

    def expire_after_loading(self, *args, **kwargs):
        original(self, *args, **kwargs)
        if any(edge["target"] == sink for edges in self.adjacent.values() for edge in edges):
            self.limit("time_limit")

    monkeypatch.setattr(traversal.TraversalSnapshot, "expand", expire_after_loading)
    result = GraphQuery(Store(graph)).paths("example.com", source, end=sink, mode="flow")
    assert result["results"] and result["truncation_reasons"] == ["time_limit"]


def test_frontier_entity_and_membership_limits(application):
    graph, _, source, _, _ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    reader.select(source, None)
    reader.selected_memberships.update(str(index) for index in range(20000))
    assert not list(reader.references([source], "forward", FLOW_KINDS))
    assert reader.metadata["truncation_reasons"] == ["relationship_limit"]
    reader.nodes.update({str(index): {} for index in range(10000)})
    reader.cache_nodes([{"id": "extra", "kind": "symbol", "url": graph.url}])
    assert "extra" not in reader.nodes and "entity_limit" in reader.metadata["truncation_reasons"]


def test_frontier_node_representatives_merge_contexts_and_accept_storage_ids(application):
    graph, _, _, _, _ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    for storage, context in (("z", "https://example.com/z"), ("a", "https://example.com/a")):
        reader.cache_nodes(
            [
                {
                    "id": storage,
                    "_logical_id": "logical",
                    "kind": "symbol",
                    "url": graph.url,
                    "name": storage,
                    "context_urls": [context],
                }
            ]
        )
    assert reader.nodes["logical"]["name"] == "z"
    assert reader.nodes["logical"]["context_urls"] == ["https://example.com/a", "https://example.com/z"]
    assert reader.select("a", None) == ["logical"]


@pytest.mark.parametrize("kind", ["ids", "limit", "terminal", "syntax", "timeout"])
def test_frontier_database_failure_handling(application, kind, monkeypatch):
    graph, *_ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    calls = []

    def read(statement, **parameters):
        calls.append(parameters)
        if kind == "ids" and len(parameters["ids"]) == 1 or kind == "limit" and parameters["limit"] == 1:
            return [{"ok": True}]
        if kind == "timeout":
            reader.started -= 121
        code = {
            "syntax": "Neo.ClientError.Statement.SyntaxError",
            "timeout": "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration",
        }.get(kind, "Neo.TransientError.General.MemoryPoolOutOfMemoryError")
        raise Neo4jError._hydrate_neo4j(code=code, message="test failure")

    monkeypatch.setattr(reader.store, "read", read)
    if kind == "syntax":
        with pytest.raises(Neo4jError):
            reader.read("test")
    else:
        rows = reader.read("test", ids=["a", "b"] if kind == "ids" else ["a"], limit=4 if kind == "limit" else 1)
        assert len(rows) == (2 if kind == "ids" else 1 if kind == "limit" else 0)
        assert len(calls) == (3 if kind in {"ids", "limit"} else 1)
        if kind in {"terminal", "timeout"}:
            assert reader.metadata["truncation_reasons"] == ["memory_limit" if kind == "terminal" else "time_limit"]


def test_frontier_missing_context_and_hydration_gap_reporting(application, monkeypatch):
    graph, _, source, _, _ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    reader.cache_nodes([{"id": "missing", "kind": "symbol", "url": graph.url, "context_owner_id": "absent"}])
    # The test store normally supplies context metadata; simulate a missing immutable owner.
    monkeypatch.setattr(reader, "read", lambda *a, **kw: [])
    reader.cache_nodes([{"id": "other", "kind": "symbol", "url": graph.url, "context_owner_id": "unknown"}])
    assert "other" not in reader.nodes
    assert "generation_unavailable" in reader.metadata["truncation_reasons"]
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    reader.select(source, None)
    monkeypatch.setattr(
        reader.service, "hydrate", lambda *a, **kw: ([], ["missing generation"], ["generation_unavailable"])
    )
    assert not reader.load([source], "forward", FLOW_KINDS)
    assert "missing generation" in reader.metadata["analysis_gaps"]


def test_memory_splitting_preserves_global_keyset_pages(event, monkeypatch):
    graph = Projection(event())
    first = graph.node("symbol", "first")
    second = graph.node("symbol", "second")
    target = graph.node("symbol", "target")
    for index in range(1200):
        graph.fact(first if index % 2 else second, target, "FLOWS_TO", "test", location=str(index))
    store = Store(graph)
    read = store.read

    def split(statement, **parameters):
        if len(parameters.get("ids", [])) > 1:
            raise Neo4jError._hydrate_neo4j(
                code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="split anchors"
            )
        return read(statement, **parameters)

    monkeypatch.setattr(store, "read", split)
    reader = TraversalSnapshot(GraphQuery(store), "example.com")
    edges = reader.load([first, second], "forward", FLOW_KINDS)
    assert len(edges) == 1200
    assert not reader.metadata["retrieval_truncated"]


def test_scope_checks_use_each_membership_context_not_merged_logical_context(application, monkeypatch):
    graph, _, source, _, _ = application
    reader = TraversalSnapshot(GraphQuery(Store(graph)), "example.com")
    reader.select(source, None)
    reader.nodes[source]["context_urls"] = [graph.url]
    hydrate = reader.service.hydrate

    def outside_source(*args, **kwargs):
        rows, gaps, reasons = hydrate(*args, **kwargs)
        for row in rows:
            row["source"] = {**row["source"], "url": "https://cdn.other.test/app.js"}
            row["source_context_urls"] = []
        return rows, gaps, reasons

    monkeypatch.setattr(reader.service, "hydrate", outside_source)
    assert not reader.load([source], "forward", FLOW_KINDS)
    assert reader.nodes[source]["context_urls"] == [graph.url]
