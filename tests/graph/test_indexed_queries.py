"""Small-graph parity and bounds for indexed discovery without a running database."""

import json

import pytest
from test_query import Store

from shyhurricane.graph.extract import extract
from shyhurricane.graph.lookup import context_records, reverse_host
from shyhurricane.graph.model import Projection
from shyhurricane.graph.query import GraphQuery
from shyhurricane.graph.traversal import TraversalSnapshot


class IndexedStore(Store):
    def __init__(self, graph):
        super().__init__(graph)
        self.contexts = {row["id"]: (row, node) for node in graph.nodes.values()
                         for row in context_records(node["id"], "GraphEntity", node.get("context_urls", []))}
        self.calls = []

    def read(self, statement, **parameters):
        self.calls.append((statement, parameters))
        if "traversal:lookup-state" in statement:
            return [{"ready": True}]
        if "traversal:metadata" in statement:
            return [{"gaps": self.graph.gaps, "analysis_details": json.dumps(self.graph.analysis)}]
        if "traversal:candidates" in statement:
            contexts = "MATCH (n:GraphContext)" in statement
            field = statement.split("USING INDEX SEEK n:", 1)[1].split("(", 1)[1].split(",", 1)[0]
            exact = f"n.{field} = $value" in statement
            if exact:
                assert "AND (n.id>$after)" in statement
            else:
                assert (f"n.{field}>$after_value OR "
                        f"(n.{field}=$after_value AND n.id>$after)") in statement
            records = [row for row, _ in self.contexts.values()] if contexts else list(self.graph.nodes.values())
            output = []
            for node in records:
                value = node.get(field, reverse_host(node["url"]))
                requested = parameters["value"]
                if not (value == requested if exact else value.startswith(requested)):
                    continue
                if (value, node["id"]) <= (parameters["after_value"], parameters["after"]):
                    continue
                if not contexts and not self.matches(node, parameters):
                    continue
                output.append({"seed": node, "cursor": value})
            return sorted(output, key=lambda row: (row["cursor"], row["seed"]["id"]))[:parameters["limit"]]
        if "traversal:boundary-candidates" in statement:
            ids = {edge["target"] for edge in self.graph.edges.values() if edge["source"] in parameters["ids"]}
            return [{"seed": node} for node in sorted(self.graph.nodes.values(), key=lambda node: node["id"])
                    if node["id"] in ids and node["id"] > parameters["after"]
                    and self.matches(node, parameters)][:parameters["limit"]]
        if "traversal:context-candidates" in statement or "traversal:indexed-context" in statement:
            nodes = {node["id"]: node for key, (context, node) in self.contexts.items()
                     if (key in parameters["lookup_ids"] if "lookup_ids" in parameters else
                         context["url"] in parameters["urls"])}
            return [{"seed": node} for node in sorted(nodes.values(), key=lambda node: node["id"])
                    if node["id"] > parameters["after"] and self.matches(node, parameters)][:parameters["limit"]]
        return super().read(statement, **parameters)

    @staticmethod
    def matches(node, parameters):
        return (not parameters.get("kinds") or node["kind"] in parameters["kinds"]) and (
            parameters.get("role") is None or node.get("role") == parameters["role"]
        ) and (parameters.get("url") is None or node["url"] == parameters["url"]) and (
            parameters.get("method") is None or node.get("method", "").upper() == parameters["method"]
        )


@pytest.mark.parametrize("scope", ["example.com", "https://example.com/page", "example.com:8443"])
@pytest.mark.parametrize("filters", [{}, {"kinds": ["field"]}, {"role": "source"},
                                     {"url": "https://example.com/page"}, {"context_url": "https://example.com/page"}])
def test_indexed_elements_match_legacy(event, scope, filters):
    graph = extract(event(body='<form action="/save"><input name="name"></form><script src="/app.js"></script>'))
    for node in graph.nodes.values():
        node["capture_id"] = graph.event["id"]
    graph.gaps = ["fixture gap"]
    graph.analysis = [{"mode": "full"}]
    expected = GraphQuery(Store(graph)).elements(scope, **filters)
    actual = GraphQuery(IndexedStore(graph)).elements(scope, **filters)
    assert actual["results"] == expected["results"]
    if actual["results"]:
        assert actual["analysis_gaps"] == expected["analysis_gaps"]
        assert actual["analysis_summaries"] == graph.analysis


@pytest.mark.parametrize("filters", [{}, {"method": "get"}, {"method": "post"}, {"url": "https://example.com/page"}])
def test_indexed_endpoint_summaries_match_legacy(event, filters):
    graph = extract(event(body='<form action="/save"><input name="name"></form><script src="/app.js"></script>'))
    expected = GraphQuery(Store(graph)).endpoints("example.com", detail="summary", **filters)
    store = IndexedStore(graph)
    actual = GraphQuery(store).endpoints("example.com", detail="summary", **filters)
    assert actual["results"] == expected["results"]
    assert not actual["retrieval_truncated"]
    if filters.get("url"):
        assert not any("MATCH (n:GraphContext)" in statement for statement, _ in store.calls)
        assert not any("traversal:context-candidates" in statement for statement, _ in store.calls)


def test_context_discovery_and_flow_keep_associations_out_of_paths(event):
    graph = Projection(event(url="https://cdn.other.test/app.js"))
    page = "https://example.com/page"
    script = graph.resource(graph.url)
    source = graph.node("source", "location", role="source", context_urls=[page])
    sink = graph.node("sink", "eval", role="sink", context_urls=[page])
    graph.fact(script, source, "CONTAINS", "test")
    graph.fact(script, sink, "CONTAINS", "test")
    graph.fact(source, sink, "FLOWS_TO", "test")
    store = IndexedStore(graph)
    result = GraphQuery(store).elements(page, role="source", context_url=page)
    assert [node["id"] for node in result["results"]] == [source]
    reader = TraversalSnapshot(GraphQuery(store), "example.com")
    reader.contextual(page)
    assert set(reader.nodes) == {source, sink}
    count = len(store.calls)
    reader.load([source], "forward", {"FLOWS_TO"})
    loaded = len(store.calls)
    assert loaded > count
    assert reader.load([source], "forward", {"FLOWS_TO"})
    assert len(store.calls) == loaded


@pytest.mark.parametrize("endpoints", [False, True])
def test_discovery_stops_at_result_cap_and_preserves_paging(event, endpoints):
    graph = Projection(event())
    origin = graph.node("origin", "origin")
    for index in range(1002):
        resource = graph.resource(f"https://example.com/{index:05}")
        graph.fact(resource, origin, "HOSTED_AT", "test", classification="observed")
    service = GraphQuery(IndexedStore(graph))
    result = service.endpoints("example.com", detail="summary") if endpoints else service.elements("example.com", kinds=["resource"])
    assert len(result["results"]) == 1000
    assert result["retrieval_truncated"] and "result_limit" in result["truncation_reasons"]


@pytest.mark.parametrize("label,field", [("GraphEntity", "url"), ("GraphContext", "url"),
                                         ("GraphEntity", "_reverse_host"), ("GraphContext", "reverse_host")])
@pytest.mark.parametrize("exact", [False, True])
def test_candidate_pages_advance_across_repeated_values_and_reverse_ids(event, label, field, exact):
    graph = Projection(event())
    graph.node_limit = 2000
    prefix = "https://example.com/" if field == "url" else "moc.elpmaxe."
    count = 1200
    for index in range(count):
        value = prefix if exact else f"{prefix}{index // 3:04}"
        node = {"id": f"{count - index:04}", "url": value, field: value}
        graph.nodes[node["id"]] = node
    store = IndexedStore(graph)
    if label == "GraphContext":
        store.contexts = {key: (node, node) for key, node in graph.nodes.items()}
    reader = TraversalSnapshot(GraphQuery(store), "example.com")
    pages = []
    for page in reader.lookup_pages(label, field, prefix, exact=exact):
        pages.append(page)
        assert len(pages) <= 3, "Candidate pagination revisited an earlier page"
    actual = [row["seed"]["id"] for page in pages for row in page]
    expected = [node["id"] for node in sorted(graph.nodes.values(), key=lambda node: (node[field], node["id"]))]
    assert actual == expected
    assert [len(page) for page in pages] == [500, 500, 200]
    assert not reader.metadata["retrieval_truncated"]
    assert len([call for call in store.calls if "traversal:candidates" in call[0]]) == 4
