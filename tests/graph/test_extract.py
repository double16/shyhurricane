import json
import subprocess
from pathlib import Path

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.extract import extract, run_javascript
from shyhurricane.graph.model import MAX_GRAPH_NODES, Projection


def kinds(graph):
    return {edge["kind"] for edge in graph.edges.values()}


def test_html_forms_links_base_and_overrides(event):
    graph = extract(
        event(
            body="""<html><base href="/base/"><a href="next#route">next</a>
        <link rel="modulepreload" href="app.js"><img src="image.png"><iframe src="frame"></iframe>
        <meta http-equiv="refresh" content="0; url=/new">
        <form id="form" action="save" method="POST"><input name="name"><input disabled name="skip">
        <button formaction="/override" formmethod="PUT">go</button></form><input form="form" name="outside">
        <script type="importmap">{"imports":{"app":"./app.js"}}</script></html>"""
        )
    )
    assert {"SUBMITS_TO", "LOADS", "NAVIGATES_TO", "IMPORTS"} <= kinds(graph)
    resources = [node for node in graph.nodes.values() if node["kind"] == "resource"]
    assert any(node["url"] == "https://example.com/base/save" and node["method"] == "POST" for node in resources)
    assert any(node["url"].endswith("next#route") for node in resources)
    fields = [node["name"] for node in graph.nodes.values() if node["kind"] == "field"]
    assert "outside" in fields and "skip" not in fields


def test_html_dialog_forms_do_not_create_network_journeys(event):
    graph = extract(
        event(
            body='<form method="dialog" action="/dialog"><input name="name"></form>'
            '<form method="PUT" action="/fallback"><button formaction="/skip" formmethod="dialog">go</button></form>'
        )
    )
    submits = [edge for edge in graph.edges.values() if edge["kind"] == "SUBMITS_TO"]
    assert len(submits) == 1
    target = graph.nodes[submits[0]["target"]]
    assert target["method"] == "GET" and target["url"].endswith("/fallback")


@pytest.mark.parametrize("limit,retained", [(2, set()), (3, {"element"}), (4, {"element", "resource"})])
def test_form_target_metadata_respects_node_budget(event, monkeypatch, limit, retained):
    original = Projection.__init__

    def initialize(graph, capture):
        original(graph, capture)
        graph.node_limit = limit

    monkeypatch.setattr(Projection, "__init__", initialize)
    graph = extract(event(body='<form action="/save"><input name="value"></form>'))
    forms = [node for node in graph.nodes.values() if node["kind"] == "element"]
    assert bool(forms) == ("element" in retained)
    if forms:
        assert ("form_target_url" in forms[0]) == ("resource" in retained)
    assert len(graph.nodes) <= limit
    assert "Capture entity budget reached" in graph.gaps
    assert all(edge[side] in graph.nodes for edge in graph.edges.values() for side in ("source", "target"))


def test_large_form_page_publishes_bounded_projection(event):
    body = "".join(f'<form action="/save/{index}"></form>' for index in range(5100))
    graph = extract(event(body=body))
    assert len(graph.nodes) == MAX_GRAPH_NODES
    assert "Capture entity budget reached" in graph.gaps
    assert graph.edges
    assert all(edge[side] in graph.nodes for edge in graph.edges.values() for side in ("source", "target"))


@pytest.mark.parametrize(
    "referer,mode,expected",
    [
        ("https://example.com/start", "navigate", "NAVIGATES_TO"),
        ("https://example.com/start", "no-cors", "REFERRED_REQUEST"),
        ("https://example.com/", "navigate", "REFERRED_REQUEST"),
        ("javascript:bad", "navigate", None),
    ],
)
def test_referer_semantics(event, referer, mode, expected):
    graph = extract(event(request_headers={"referer": referer, "Sec-Fetch-Mode": mode}))
    if expected:
        assert expected in kinds(graph)
    else:
        assert kinds(graph) == {"HOSTED_AT"}


def test_headers_and_request_fields(event):
    graph = extract(
        event(
            url="https://example.com/page?q=secret",
            response_code=302,
            request_headers={"Origin": "https://other.test", "Content-Type": "application/json"},
            request_body='{"name":"sensitive"}',
            response_headers={"Location": "/login", "Refresh": "0; url=/refresh", "Link": '</app.js>; rel="preload"'},
        )
    )
    assert {"REDIRECTS_TO", "NAVIGATES_TO", "SENDS_FIELD", "REQUEST_ORIGIN", "RESOURCE_LINK"} <= kinds(graph)
    assert "sensitive" not in json.dumps(list(graph.evidence.values()))
    assert extract(event(request_headers={"content-type": "application/json"}, request_body="bad")).gaps
    assert "SENDS_FIELD" in kinds(
        extract(event(request_headers={"content-type": "application/x-www-form-urlencoded"}, request_body="name=value"))
    )


def test_structured_resources(event):
    manifest = {
        "entry.js": {
            "file": "assets/entry.js",
            "imports": ["shared.js"],
            "dynamicImports": ["lazy.js"],
            "css": ["entry.css"],
            "assets": ["image.png"],
        },
        "shared.js": {"file": "assets/shared.js"},
        "lazy.js": {"file": "assets/lazy.js"},
    }
    graph = extract(event(url="https://example.com/manifest.json", body=json.dumps(manifest), mime="application/json"))
    assert "IMPORTS" in kinds(graph)
    assert any(node["url"].endswith("/assets/lazy.js") for node in graph.nodes.values())
    spec = {
        "paths": {"/api": {"get": {}, "post": {}, "parameters": []}},
        "start_url": "/home",
        "links": [{"href": "/next"}],
    }
    assert {"DECLARES_ENDPOINT", "NAVIGATES_TO", "RESOURCE_LINK"} <= kinds(
        extract(event(body=json.dumps(spec), mime="application/json"))
    )
    assert extract(event(body="bad", mime="application/json")).gaps
    assert "LOADS" in kinds(extract(event(body="@import 'style.css'; a{background:url(img.png)}", mime="text/css")))


def test_javascript_inputs_map_recovery_and_failures(graph_paths, event, monkeypatch):
    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    artifacts = ArtifactStore("db")
    mapping = {"version": 3, "sources": ["src/a.ts"], "sourcesContent": ["const x:string=location.hash"]}
    artifacts.register(event(url="https://example.com/a.js.map", body=json.dumps(mapping)))
    calls = []

    def runner(source, filename):
        calls.append((source, filename))
        return {
            "nodes": [
                {"id": "a", "name": "location.hash", "role": "source"},
                {
                    "id": "b",
                    "name": "fetch",
                    "role": "sink",
                    "import_url": "./other.js",
                    "imported_name": "send",
                    "parameter_index": 0,
                },
            ],
            "edges": [{"source": "a", "target": "b", "kind": "FLOWS_TO"}],
            "references": [{"source": "b", "url": "/next", "kind": "NAVIGATES_TO"}],
            "gaps": ["partial"],
        }

    graph = extract(
        event(url="https://example.com/a.js", body="delivered", mime="text/javascript"),
        artifacts,
        javascript_runner=runner,
    )
    assert calls == [(mapping["sourcesContent"][0], "src/a.ts")]
    assert {"FLOWS_TO", "UNRESOLVED_REFERENCE"} <= kinds(graph)
    assert "partial" in graph.gaps
    graph = extract(event(body='<script>let x=1</script><button onclick="go()"></button>'), javascript_runner=runner)
    assert len(calls) == 3
    with pytest.raises(ZeroDivisionError):
        extract(event(url="https://example.com/a.js", mime="text/javascript"), javascript_runner=lambda *a: 1 / 0)
    # Unexpected analyzer programming errors propagate to the worker's retained failure path.
    artifacts.close()


def test_analyzer_operational_failures_and_limits(event, monkeypatch, caplog):
    def fail(*args):
        raise subprocess.TimeoutExpired("node", 1)

    assert (
        "unavailable"
        in extract(event(url="https://example.com/a.js", mime="text/javascript"), javascript_runner=fail).gaps[0]
    )
    assert "JavaScript analysis failed error=TimeoutExpired" in caplog.text
    monkeypatch.setattr("shyhurricane.graph.extract.MAX_BYTES", 2)
    assert "limit" in extract(event(body="long")).gaps[0]
    assert extract({**event(), "backfill": True}).gaps
    monkeypatch.setattr(
        "shyhurricane.graph.extract.subprocess.run", lambda *a, **kw: type("Result", (), {"stdout": '{"nodes":[]}'})()
    )
    assert run_javascript("source", "a.js") == {"nodes": []}


def test_real_ast_output_connects_to_projection(event):
    analyzer = Path("src/docker/unix_command/graph-analysis/analyze.cjs").resolve()

    def runner(source, filename):
        return json.loads(
            subprocess.run(
                ["node", str(analyzer)],
                input=json.dumps({"source": source, "filename": filename}),
                text=True,
                capture_output=True,
                check=True,
            ).stdout
        )

    graph = extract(
        event(url="https://example.com/app.js", body="const x=location.hash; eval(x);", mime="text/javascript"),
        javascript_runner=runner,
    )
    assert "FLOWS_TO" in kinds(graph)
    assert any(node.get("role") == "sink" for node in graph.nodes.values())


def test_supplied_forms_cookie_scopes_and_policies(event):
    graph = extract(
        event(
            forms=["invalid", {"action": "/save", "method": "POST", "inputs": ["name", {"name": "other"}]}],
            request_headers={"Cookie": "session=secret"},
            response_headers={
                "Set-Cookie": "session=secret; Path=/; Secure; HttpOnly",
                "Content-Security-Policy": "connect-src https://api.example.com; script-src 'self'",
                "Access-Control-Allow-Origin": "https://other.example.com",
            },
        )
    )
    assert {"SUBMITS_TO", "SETS_COOKIE", "SENDS_COOKIE", "ALLOWS_ORIGIN", "ALLOWS_CONNECTION"} <= kinds(graph)
    assert "secret" not in json.dumps(list(graph.evidence.values()))


def test_map_fallbacks_and_recovered_imports(event, graph_paths, monkeypatch):
    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    artifacts = ArtifactStore("db")
    artifacts.register(event(url="https://example.com/a.js.map", body='{"version":3,"sources":[]}'))
    graph = extract(
        event(url="https://example.com/a.js", mime="text/javascript", body="x"),
        artifacts,
        javascript_runner=lambda *a: {"nodes": [], "edges": [], "references": []},
    )
    assert any("no embedded" in gap for gap in graph.gaps)
    assert extract(event(url="https://example.com/a.js.map", body="bad", mime="application/json")).gaps
    graph = extract(
        event(
            url="https://example.com/b.js.map",
            mime="application/json",
            body=json.dumps({"sources": ["src/a.ts"], "sourcesContent": ["source"]}),
        ),
        artifacts,
        javascript_runner=lambda *a: {
            "nodes": [],
            "edges": [],
            "references": [{"url": "./b.ts", "kind": "IMPORTS"}, {"url": "https://api.test/", "kind": "REQUESTS"}],
        },
    )
    assert "IMPORTS" in kinds(graph)
    assert any(node["kind"] == "module_reference" for node in graph.nodes.values())
    assert extract(event(body='<script type="importmap">bad</script>')).gaps
    artifacts.close()


def test_summary_policy_cache_separation_and_source_preparation(graph_paths, event, monkeypatch):
    from shyhurricane.graph.artifacts import ArtifactStore

    source = "standalone trusted library"
    artifacts = ArtifactStore("db")
    monkeypatch.setattr(artifacts, "source_map", lambda *args, **kwargs: None)
    deobfuscated = []
    monkeypatch.setattr(artifacts, "deobfuscate", lambda body, fn: deobfuscated.append(body) or body)
    calls = []

    def run(*args, **kwargs):
        request = json.loads(kwargs["input"])
        calls.append(request)
        result = {
            "nodes": [],
            "edges": [],
            "references": [],
            "analysis": {
                "mode": request["mode"],
                "retained_nodes": 0,
                "retained_edges": 0,
            },
        }
        return type("Result", (), {"stdout": json.dumps(result)})()

    monkeypatch.setattr("shyhurricane.graph.extract.subprocess.run", run)
    capture = event(url="https://example.com/renamed.js", mime="text/javascript", body=source)
    first = extract(capture, artifacts)
    assert first.analysis[0]["mode"] == "summary" and deobfuscated == [source]
    extract(capture, artifacts)
    assert len(calls) == 1
    full = extract({**capture, "library_analysis": "full"}, artifacts)
    assert full.analysis[0]["mode"] == "full" and deobfuscated == [source, source, source]
    assert "library" not in full.analysis[0]
    assert len(calls) == 2 and calls[-1]["mode"] == "full"
    artifacts.close()


def test_library_publication_budgets_do_not_leave_dangling_edges_or_leak_to_other_scripts(event):
    from shyhurricane.graph.model import MAX_GRAPH_EDGES, MAX_GRAPH_NODES

    nodes = [{"id": str(index), "name": str(index), "role": "sink"} for index in range(1100)]
    edges = [
        {"source": str(index), "target": str((index + offset) % 1100), "kind": "FLOWS_TO"}
        for index in range(1100)
        for offset in (1, 2)
    ]
    output = {"nodes": nodes, "edges": edges, "references": [], "analysis": {"mode": "summary", "library": "Fixture"}}
    graph = extract(
        event(url="https://example.com/library.js", mime="text/javascript"), javascript_runner=lambda *a: output
    )
    assert len(graph.nodes) <= 1002 and len(graph.edges) <= 2001
    assert all(edge["source"] in graph.nodes and edge["target"] in graph.nodes for edge in graph.edges.values())
    assert graph.node_limit == MAX_GRAPH_NODES and graph.edge_limit == MAX_GRAPH_EDGES
    assert graph.analysis[0]["budget_limited"]
    assert graph.analysis[0]["published_nodes"] == 1000
    assert any("budget reached" in gap for gap in graph.gaps)
    resource = next(node for node in graph.nodes.values() if node["kind"] == "resource")
    assert json.loads(resource["analysis_details"])[0]["published_nodes"] == 1000


def test_form_successful_controls_respect_fieldsets_submitters_and_explicit_owners(event):
    graph = extract(
        event(
            body="""<form id="one" name="first" action="/save">
      <fieldset disabled><legend><input name="legend"></legend><input name="outsideLegend"></fieldset>
      <fieldset disabled><input name="noLegend"></fieldset>
      <input name="checked" type="checkbox" checked><input name="unchecked" type="checkbox">
      <input name="radio" type="radio"><input name="submit" type="submit"><button name="button">Go</button>
      <input name="wrong" form="other"><input name="none" form=""><textarea name="text"></textarea>
      </form><input name="external" form="one"><form id="other"><input name="otherField"></form>"""
        )
    )
    controls = {node["field_name"]: node for node in graph.nodes.values() if node.get("field_name")}
    for name in ("legend", "checked", "text", "external", "otherField"):
        assert controls[name]["form_successful"]
    for name in ("outsideLegend", "noLegend", "unchecked", "radio", "submit", "button"):
        assert not controls[name]["form_successful"]
    assert controls["none"]["form_selectors"] == []
    assert controls["wrong"]["form_selectors"] == ["#other"]
    assert controls["external"]["form_selectors"] == ["#one", 'form[name="first"]']
    submitted = {
        graph.nodes[edge["source"]]["name"]
        for edge in graph.edges.values()
        if graph.evidence[edge["evidence_id"]]["rule"] == "html.form-field"
    }
    assert submitted == {"legend", "checked", "text", "external", "otherField", "wrong"}


def test_summary_edges_keep_distinct_path_evidence_and_auxiliary_allowance(event):
    output = {
        "nodes": [
            {"id": "source", "role": "source", "name": "input", "callback_boundary": True},
            {"id": "sink", "role": "sink", "name": "eval"},
            {"id": "other", "role": "sink", "name": "write"},
        ],
        "edges": [
            {
                "source": "source",
                "target": target,
                "kind": "SUMMARIZED_FLOW",
                "rule": "js.size-summary",
                "location": "1:0",
                "snippet": "Intermediate operations omitted",
                "original_hops": hops,
                "endpoint_locations": ["1:0", "20:0"],
                "witness": [f"source -> {target}"],
                "summary_notice": "Static reachability; intermediate operations omitted",
            }
            for target, hops in (("sink", 20), ("other", 30))
        ],
        "references": [{"source": "source", "url": "https://example.com/api", "kind": "REQUESTS"}],
        "analysis": {"mode": "summary", "trigger": "graph_size", "budget_limited": False},
    }
    graph = extract(
        event(url="https://example.com/app.js", mime="text/javascript"), javascript_runner=lambda *args: output
    )
    summaries = [edge for edge in graph.edges.values() if edge["kind"] == "SUMMARIZED_FLOW"]
    assert len(summaries) == 2
    assert len({edge["evidence_id"] for edge in summaries}) == 2
    for edge in summaries:
        proof = graph.evidence[edge["evidence_id"]]
        assert proof["original_hops"] == edge["original_hops"]
        assert proof["witness"] == edge["witness"]
        assert proof["endpoint_locations"] == ["1:0", "20:0"]
        assert proof["classification"] == "statically_inferred"
        assert "omitted" in proof["summary_notice"]
    assert "REQUESTS" in kinds(graph)
    assert any(node.get("callback_boundary") for node in graph.nodes.values())
    assert graph.analysis[0]["publication_limited"] is False
    assert graph.analysis[0]["budget_limited"] is False


def test_summary_source_map_recovery_is_not_skipped(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    source_map = json.dumps({"version": 3, "sources": ["node_modules/react/index.js", "app.js"],
                             "sourcesContent": ["export const React = {};", "eval(location.hash)"]})
    monkeypatch.setattr(artifacts, "source_map", lambda *args, **kwargs: source_map)
    monkeypatch.setattr(artifacts, "deobfuscate", lambda *args: pytest.fail("Recovered sources need no deobfuscation"))
    seen = []

    def runner(source, filename):
        seen.append((source, filename))
        return {"nodes": [], "edges": [], "references": [], "analysis": {"mode": "full"}}

    graph = extract(event(url="https://example.com/vendor.js", mime="text/javascript", body="/* React */"),
                    artifacts, javascript_runner=runner)
    assert [source for source, _ in seen] == ["export const React = {};", "eval(location.hash)"]
    assert len(graph.analysis) == 2
    artifacts.close()


@pytest.mark.parametrize("budget", ["nodes", "edges"])
def test_summary_reports_existing_capture_limits_and_prioritizes_flows(event, budget):
    from shyhurricane.graph.extract import apply_javascript

    graph = extract(event(body=""))
    page = next(key for key, value in graph.nodes.items() if value["kind"] == "resource")
    output = {
        "nodes": [{"id": "s", "role": "source"}, {"id": "t", "role": "sink"}],
        "edges": [{"source": "s", "target": "t", "kind": "FLOWS_TO"}],
        "references": [],
        "analysis": {"mode": "summary", "budget_limited": False},
    }
    if budget == "nodes":
        graph.node_limit = len(graph.nodes)
        graph.gaps.append("Capture entity budget reached")
    else:
        graph.edge_limit = len(graph.edges) + 1
    limits = graph.node_limit, graph.edge_limit
    for filename in ("first.js", "second.js"):
        apply_javascript(graph, page, filename, output, lambda *args, **kwargs: None, [])
        assert graph.analysis[-1]["publication_limited"]
        assert graph.analysis[-1]["budget_limited"]
        assert (graph.node_limit, graph.edge_limit) == limits
    if budget == "edges":
        assert any(edge["kind"] == "FLOWS_TO" for edge in graph.edges.values())
    assert all(edge["source"] in graph.nodes and edge["target"] in graph.nodes for edge in graph.edges.values())
