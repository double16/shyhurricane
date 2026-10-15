import pytest

from shyhurricane.graph.extract import extract
from shyhurricane.graph.query import GraphQuery, scope_predicate


class Store:
    def __init__(self, graph):
        self.graph = graph

    def read(self, statement, **parameters):
        if "GraphEvidence" in statement:
            evidence = self.graph.evidence.get(parameters["id"])
            return [{"evidence": evidence}] if evidence else []
        if "AS membership_id" in statement:
            return [
                {"membership_id": edge["id"], "capture_id": self.graph.event["id"], "publication_id": None}
                for edge in self.graph.edges.values()
            ]
        if "AS node" in statement:
            return [{"node": self.graph.nodes[key]} for key in parameters["ids"] if key in self.graph.nodes]
        if "AS publication_id" in statement:
            return [
                {
                    "capture_id": owner["capture"],
                    "publication_id": owner["publication"],
                    "gaps": self.graph.gaps,
                    "observed_at": self.graph.event["observed_at"],
                }
                for owner in parameters["owners"]
            ]
        if "AS context_urls" in statement:
            return [{"id": owner["id"], "context_urls": []} for owner in parameters["contexts"]]
        return [
            {
                "source_id": edge["source"],
                "target_id": edge["target"],
                "relationship": edge,
            }
            for edge in self.graph.edges.values()
            if edge["id"] in parameters["ids"]
        ]


def test_normalized_capture_context_preserves_cdn_scope_and_evidence(event):
    graph = extract(
        event(url="https://cdn.example.net/main.js", mime="text/javascript"), javascript_runner=lambda *a: {}
    )
    store = Store(graph)
    for node in graph.nodes.values():
        node["context_owner_id"] = "context"
    original = store.read

    def read(statement, **parameters):
        rows = original(statement, **parameters)
        for row in rows:
            if "evidence" in row or "context_urls" in row:
                row["context_urls"] = ["https://example.com/form"]
            else:
                row["source_context_urls"] = ["https://example.com/form"]
                row["target_context_urls"] = ["https://example.com/form"]
        return rows

    store.read = read
    service = GraphQuery(store)
    result = service.elements("https://example.com/form", detail="full")
    assert result["results"]
    assert all(node["context_urls"] == ["https://example.com/form"] for node in result["results"])
    evidence_id = next(iter(graph.evidence))
    assert service.evidence("example.com", evidence_id)["context_urls"] == ["https://example.com/form"]
    assert service.evidence("unrelated.com", evidence_id) is None


@pytest.mark.parametrize(
    "scope,url,expected",
    [
        ("example.com", "https://sub.example.com/a", True),
        ("example.com", "https://badexample.com/a", False),
        ("example.com:8443", "https://example.com/a", False),
        ("https://example.com/a", "https://example.com/abc", True),
        ("https://example.com/a", "http://example.com/a", False),
        ("[::1]:8080", "http://[::1]:8080/a", True),
    ],
)
def test_scope_boundaries(scope, url, expected):
    assert scope_predicate(scope)(url) is expected


@pytest.mark.parametrize(
    "scope", ["", "https://user:password@example.com", "ftp://example.com", "https://x/?q=1", "x:bad"]
)
def test_invalid_scopes(scope):
    with pytest.raises(ValueError):
        scope_predicate(scope)


def test_journeys_exclude_assets_and_return_evidence(event):
    graph = extract(event(body='<a href="/next">next</a><script src="/asset.js"></script>'))
    service = GraphQuery(Store(graph))
    result = service.paths("example.com", graph.url, end="https://example.com/next", mode="journey")
    assert len(result["results"]) == 1
    step = result["results"][0]["steps"][0]
    assert service.evidence("example.com", step["evidence_id"])["rule"] == "html.link"
    assert not service.paths("example.com", graph.url, end="https://example.com/asset.js", mode="journey")["results"]
    assert service.evidence("other.test", step["evidence_id"]) is None
    assert service.evidence("example.com", "missing") is None
    assert service.paths("example.com", "missing")["analysis_gaps"]
    assert service.paths("example.com", graph.url, end="missing")["analysis_gaps"]


def test_flow_directions_filters_and_cycle_budgets(event, monkeypatch):
    graph = extract(event())
    source = graph.node("field", "input", role="source")
    mid = graph.node("symbol", "value")
    sink = graph.node("sink", "eval", role="sink")
    graph.fact(source, mid, "FLOWS_TO", "test")
    graph.fact(mid, sink, "CALL_ARGUMENT", "test")
    graph.fact(mid, source, "FLOWS_TO", "test")
    service = GraphQuery(Store(graph))
    assert service.paths("example.com", source, mode="flow")["results"]
    assert service.paths("example.com", sink, mode="flow", direction="backward")["results"]
    assert not service.paths("example.com", source, mode="flow", kinds=["NAVIGATES_TO"])["results"]
    assert service.paths("example.com", source, mode="flow", max_depth=1)["retrieval_truncated"]
    assert service.elements("example.com", kinds=["field"], role="source", url=graph.url)["results"][0]["id"] == source
    assert not service.elements("other.test")["results"]
    with pytest.raises(ValueError):
        service.paths("example.com", source, direction="sideways")
    with pytest.raises(ValueError):
        service.paths("example.com", source, max_depth=33)
    monkeypatch.setattr("shyhurricane.graph.query.MAX_ENTITIES", 1)
    assert service.elements("example.com")["retrieval_truncated"]


def test_relationship_filters_external_boundaries_and_result_cap(event, monkeypatch):
    graph = extract(event(body='<a href="https://other.test/">external</a><a href="/local">local</a>'))
    service = GraphQuery(Store(graph))
    assert len(service.paths("example.com", graph.url, kinds=["NAVIGATES_TO"])["results"]) == 2
    assert not service.elements("example.com", url="https://example.com/missing")["results"]
    monkeypatch.setattr("shyhurricane.graph.query.MAX_RESULTS", 1)
    assert service.elements("example.com")["retrieval_truncated"]
    assert service.paths("example.com", graph.url)["retrieval_truncated"]


def test_snapshot_hydration_uses_bounded_reads_and_reports_missing_generations(event):
    from shyhurricane.graph.model import Projection

    graph = Projection(event())
    source = graph.resource(graph.url)
    for index in range(501):
        target = graph.node("symbol", str(index))
        graph.fact(source, target, "FLOWS_TO", "test", location=str(index))
    store = Store(graph)
    original = store.read
    calls = []

    def read(statement, **parameters):
        calls.append(parameters)
        return original(statement, **parameters)

    store.read = read
    result = GraphQuery(store).snapshot("example.com")
    assert len(result[1]) == 501
    assert all(
        len(value) <= 500 for call in calls for key, value in call.items() if key in {"ids", "owners", "contexts"}
    )

    def missing(statement, **parameters):
        rows = original(statement, **parameters)
        return rows[1:] if "AS node" in statement else rows

    store.read = missing
    metadata = GraphQuery(store).snapshot("example.com")[2]
    assert metadata["retrieval_truncated"]
    assert "generation_unavailable" in metadata["truncation_reasons"]


def test_snapshot_hydration_time_budget_returns_explicit_incompleteness(event, monkeypatch):
    from shyhurricane.graph import query

    graph = extract(event(body='<a href="/next">next</a>'))
    store = Store(graph)
    references = store.read("AS membership_id")
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        return 0 if calls == 1 else 121

    monkeypatch.setattr(query.time, "monotonic", clock)
    rows, gaps, reasons = GraphQuery(store).hydrate(references)
    assert not rows and gaps and reasons == ["time_limit"]


def test_snapshot_hydration_subdivides_memory_errors_and_reports_terminal_records(event):
    from neo4j.exceptions import Neo4jError

    graph = extract(event(body='<a href="/a">a</a><a href="/b">b</a>'))
    store = Store(graph)
    read = store.read

    def memory_error():
        return Neo4jError._hydrate_neo4j(code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget")

    def limited(statement, **parameters):
        if "ids" in parameters and len(parameters["ids"]) > 1:
            raise memory_error()
        return read(statement, **parameters)

    store.read = limited
    result = GraphQuery(store).snapshot("example.com")
    assert len(result[1]) == len(graph.edges) and not result[2]["retrieval_truncated"]

    def blocked(statement, **parameters):
        if "AS node" in statement:
            raise memory_error()
        return read(statement, **parameters)

    store.read = blocked
    metadata = GraphQuery(store).snapshot("example.com")[2]
    assert metadata["retrieval_truncated"] and metadata["truncation_reasons"] == ["memory_limit"]

    def other_error(statement, **parameters):
        if "AS node" in statement:
            raise Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
        return read(statement, **parameters)

    store.read = other_error
    with pytest.raises(Neo4jError):
        GraphQuery(store).snapshot("example.com")


def test_library_analysis_metadata_is_exposed_in_queries_and_evidence(event):
    import json

    graph = extract(event(body='<a href="/next">next</a>'))
    analysis = [{"library": "Fixture", "mode": "summary", "omitted_nodes": 100}]

    class AnalysisStore(Store):
        def read(self, statement, **parameters):
            rows = super().read(statement, **parameters)
            if "AS analysis_details" in statement:
                for row in rows:
                    row["analysis_details"] = json.dumps(analysis)
            return rows

    service = GraphQuery(AnalysisStore(graph))
    assert service.snapshot("example.com")[2]["analysis_summaries"] == analysis
    proof = next(iter(graph.evidence))
    assert service.evidence("example.com", proof)["analysis_summaries"] == analysis


def test_endpoint_overview_uses_captured_http_fields_and_resource_identity(event):
    graph = extract(
        event(
            url="https://example.com/stock?product=1",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"quantity": 2}',
            body='<a href="/next">next</a>',
        )
    )
    service = GraphQuery(Store(graph))
    (endpoint,) = service.endpoints("example.com", url=graph.url, method="post")["results"]
    assert endpoint["capture_status"] == "captured" and endpoint["method"] == "POST"
    assert {node["name"] for node in endpoint["inputs"]["examples"]} == {"product", "quantity"}
    assert endpoint["sources"]["examples"][0]["name"] == "product"
    assert endpoint["sinks"]["examples"][0]["name"] == "quantity"
    assert endpoint["scripts"]["follow_up"] == []
    (referenced,) = service.endpoints("example.com", url="https://example.com/next")["results"]
    assert referenced["capture_status"] == "referenced"
    assert not service.paths("example.com", endpoint["id"], mode="flow")["results"]
