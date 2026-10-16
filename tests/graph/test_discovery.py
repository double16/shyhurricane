"""Endpoint discovery, compact presentation, and resource flow entry points."""

import pytest

from shyhurricane.graph.discovery import ResourceDiscovery, present
from shyhurricane.graph.extract import extract
from shyhurricane.graph.query import GraphQuery


@pytest.fixture
def application(event):
    graph = extract(
        event(
            url="https://example.com/blog",
            body='<form action="/submit" method="post"><input name="product"></form>'
            '<script src="/app.js"></script><a href="https://outside.test/">outside</a>',
        )
    )
    page = graph.resource(graph.url)
    script = graph.resource("https://example.com/app.js")
    source = graph.node(
        "source",
        "hash",
        url=graph.nodes[script]["url"],
        role="source",
        name="location.hash",
        context_urls=[graph.url],
        source_path="app.js",
        location="1:1",
        import_key="internal",
    )
    sink = graph.node(
        "sink",
        "eval",
        url=graph.nodes[script]["url"],
        role="sink",
        name="eval",
        context_urls=[graph.url],
        source_path="app.js",
        location="2:1",
    )
    graph.nodes[script]["context_urls"] = [graph.url]
    graph.fact(script, source, "CONTAINS", "test.source")
    graph.fact(script, sink, "CONTAINS", "test.sink")
    graph.fact(source, sink, "FLOWS_TO", "test.flow", location="1:1")
    other = graph.resource("https://example.com/unrelated")
    separate = graph.node("source", "separate", url="https://example.com/other.js", role="source")
    graph.fact(other, separate, "CONTAINS", "test.other")
    service = GraphQuery(None)
    calls = []

    def snapshot(scope, **kwargs):
        calls.append((scope, kwargs))
        return (
            graph.nodes,
            list(graph.edges.values()),
            {
                "instructions": "Captured candidates. ",
                "analysis_gaps": [],
                "retrieval_truncated": False,
                "truncation_reasons": [],
            },
        )

    service.snapshot = snapshot
    return graph, service, page, script, source, sink, separate, calls


def test_overview_resources_methods_contexts_and_scope(application):
    graph, service, page, script, source, sink, separate, calls = application
    overview = service.endpoints("example.com", url=graph.url, method="get", historical=True, as_of=42)
    assert calls == [("example.com", {"historical": True, "as_of": 42})]
    (endpoint,) = overview["results"]
    assert endpoint["id"] == page and endpoint["capture_status"] == "captured"
    assert endpoint["inputs"]["count"] >= 1
    assert endpoint["scripts"]["examples"][0]["id"] == script
    assert source in {item["id"] for item in endpoint["sources"]["examples"]}
    assert sink in {item["id"] for item in endpoint["sinks"]["examples"]}
    assert separate not in {item["id"] for item in endpoint["sources"]["examples"]}
    assert endpoint["sinks"]["examples"][0]["association"] == "script_context"
    assert endpoint["sources"]["follow_up"][0]["arguments"]["context_url"] == graph.url
    assert not service.endpoints("example.com", url=graph.url, method="post")["results"]
    endpoint = service.endpoints("example.com", url="https://example.com/submit", method="POST")["results"][0]
    assert endpoint["capture_status"] == "referenced"
    assert endpoint["inputs"]["count"] == 1
    graph.resource("https://example.com/submit", "GET")
    resources = service.endpoints("example.com")["results"]
    assert [item["method"] for item in resources if item["url"].endswith("/submit")] == ["GET", "POST"]
    assert resources == sorted(resources, key=lambda item: (item["url"], item["method"], item["id"]))
    assert not service.endpoints("unrelated.test")["results"]
    assert not service.endpoints("example.com", url="https://example.com/missing")["results"]
    assert all(item["url"] != "https://outside.test/" for item in resources)
    assert "bounded snapshot" in overview["instructions"]


def test_overview_bounded_examples_and_result_caps(application, monkeypatch):
    graph, service, page, _, _, _, _, _ = application
    for index in range(5):
        node = graph.node("field", f"input-{index}", role="source")
        graph.fact(node, page, "SENDS_FIELD", "test.field", location=str(index))
    endpoint = service.endpoints("example.com", url=graph.url)["results"][0]
    assert endpoint["inputs"]["count"] > 3
    assert len(endpoint["inputs"]["examples"]) == 3
    assert endpoint["inputs"]["examples_limited"]
    assert {call["arguments"]["direction"] for call in endpoint["inputs"]["follow_up"]} == {"forward", "backward"}
    monkeypatch.setattr("shyhurricane.graph.query.MAX_RESULTS", 1)
    result = service.endpoints("example.com")
    assert len(result["results"]) == 1 and result["retrieval_truncated"]
    assert result["truncation_reasons"] == ["result_limit"]


def test_compact_full_and_context_filters(application):
    graph, service, page, _, source, sink, separate, _ = application
    compact = service.elements("example.com", role="source", context_url=graph.url)
    full = service.elements("example.com", role="source", context_url=graph.url, detail="full")
    assert [item["id"] for item in compact["results"]] == [item["id"] for item in full["results"]]
    assert source in {item["id"] for item in compact["results"]}
    assert separate not in {item["id"] for item in compact["results"]}
    assert not service.elements("example.com", context_url=graph.url + "/other")["results"]
    assert source not in {item["id"] for item in service.elements("example.com", url=graph.url)["results"]}
    assert "import_key" not in next(item for item in compact["results"] if item["id"] == source)
    assert "import_key" in next(item for item in full["results"] if item["id"] == source)
    assert service.elements("example.com")["results"][0]["kind"] == "resource"
    assert service.elements("example.com", kinds=["sink"])["results"][0]["id"] == sink
    for operation in (
        lambda: service.elements("example.com", detail="invalid"),
        lambda: service.paths("example.com", page, detail="invalid"),
    ):
        with pytest.raises(ValueError, match="detail must"):
            operation()
    assert present({"id": source, "key": "private"}, "compact") == {"id": source}


@pytest.mark.parametrize("backward", [False, True])
@pytest.mark.parametrize("use_id", [False, True])
def test_resource_flow_seeds_and_real_edges(application, backward, use_id):
    graph, service, page, _, source, sink, _, _ = application
    entry = page if use_id else graph.url
    direction = "backward" if backward else "forward"
    result = service.paths("example.com", entry, end=entry, mode="flow", direction=direction)
    assert result["resolved_start_ids"] == [sink] if backward else source in result["resolved_start_ids"]
    assert source in result["resolved_end_ids"] if backward else result["resolved_end_ids"] == [sink]
    (path,) = result["results"]
    assert [node["id"] for node in path["nodes"]] == ([sink, source] if backward else [source, sink])
    assert [step["kind"] for step in path["steps"]] == ["FLOWS_TO"]
    full = service.paths("example.com", entry, end=entry, mode="flow", direction=direction, detail="full")
    assert full["results"][0]["steps"][0]["evidence_id"] == path["steps"][0]["evidence_id"]
    assert "capture_id" not in path["steps"][0] and "capture_id" in full["results"][0]["steps"][0]
    assert "flow edges" in result["instructions"]


def test_explicit_elements_no_path_missing_seeds_and_seed_limits(application):
    graph, service, page, _, source, sink, separate, _ = application
    assert service.paths("example.com", source, mode="flow")["resolved_start_ids"] == [source]
    assert service.paths("example.com", sink, mode="flow", direction="backward")["results"]
    missing = service.paths("example.com", "missing", end="also missing", mode="flow")
    assert len(missing["analysis_gaps"]) == 2
    isolated = service.paths("example.com", separate, mode="flow")
    assert isolated["resolved_start_count"] == 1 and not isolated["results"]
    assert "no discovered path" in isolated["analysis_gaps"][0]
    empty = graph.resource("https://example.com/empty")
    assert not service.paths("example.com", empty, mode="flow")["resolved_start_ids"]
    assert service.paths("example.com", graph.url, mode="relationships")["results"]
    for index in range(21):
        node = graph.node("source", f"source-{index}", role="source")
        graph.fact(page, node, "CONTAINS", "test.seed", location=str(index))
    result = service.paths("example.com", page, mode="flow")
    assert result["resolved_start_count"] > 20 and len(result["resolved_start_ids"]) == 20
    assert result["seed_ids_limited"]


def test_script_context_does_not_merge_other_pages_or_methods(application):
    graph, service, page, script, source, sink, separate, _ = application
    other = graph.resource("https://example.com/other")
    graph.nodes[source]["context_urls"].append(graph.nodes[other]["url"])
    discovery = ResourceDiscovery(graph.nodes, list(graph.edges.values()))
    assert source in discovery.select(other, "source")
    assert sink not in discovery.select(other, "sink")
    post = graph.resource(graph.url, "POST")
    field = graph.node("field", "posted", role="sink")
    graph.fact(post, field, "SENDS_FIELD", "http.body")
    discovery = ResourceDiscovery(graph.nodes, list(graph.edges.values()))
    assert field in discovery.select(post, "sink")
    assert field not in discovery.select(page, "sink")
    assert discovery.select(script) == [script]
    assert discovery.select("https://example.com/not-found") == []


def test_association_alone_never_becomes_a_flow_path(application):
    graph, service, page, _, source, sink, _, _ = application
    graph.edges = {key: edge for key, edge in graph.edges.items() if edge["kind"] != "FLOWS_TO"}
    result = service.paths("example.com", page, mode="flow")
    assert source in result["resolved_start_ids"]
    assert not result["results"]
    assert "no discovered path" in result["analysis_gaps"][0]
    assert not service.paths("example.com", source, end=sink, mode="flow")["results"]


def test_extensionless_scripts_and_inline_code_are_distinguished(application):
    graph, service, page, _, _, _, _, _ = application
    runtime_url = "https://example.com/runtime"
    runtime = graph.resource(runtime_url)
    source = graph.node(
        "source", "runtime-source", url=runtime_url, source_path=runtime_url, role="source", name="aaa-runtime"
    )
    graph.fact(runtime, source, "CONTAINS", "runtime.source")
    graph.fact(page, runtime, "LOADS", "runtime.load")
    inline = graph.node("sink", "inline", source_path="html:1:script", role="sink")
    graph.fact(page, inline, "CONTAINS", "html.inline")
    graph.nodes[page]["context_urls"] = [graph.url]
    endpoint = service.endpoints("example.com", url=graph.url)["results"][0]
    scripts = {node["id"] for node in endpoint["scripts"]["examples"]}
    assert runtime in scripts and page not in scripts
    assert inline in {node["id"] for node in endpoint["sinks"]["examples"]}
    assert source in {node["id"] for node in endpoint["sources"]["examples"]}
