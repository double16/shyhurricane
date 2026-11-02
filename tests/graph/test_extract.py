import base64
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
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: source)
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
        event(url="https://example.com/a.js",
              body="//# sourceMappingURL=data:application/json;base64," +
              base64.b64encode(json.dumps(mapping).encode()).decode(), mime="text/javascript"),
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
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: source)
    artifacts = ArtifactStore("db")
    artifacts.register(event(url="https://example.com/a.js.map", body='{"version":3,"sources":[]}'))
    graph = extract(
        event(url="https://example.com/a.js", mime="text/javascript", body="x"),
        artifacts,
        javascript_runner=lambda *a: {"nodes": [], "edges": [], "references": []},
    )
    assert any("unverified" in gap for gap in graph.gaps)
    assert extract(event(url="https://example.com/a.js.map", body="bad", mime="application/json")).gaps
    graph = extract(
        event(
            url="https://example.com/b.js",
            mime="text/javascript",
            body="//# sourceMappingURL=data:application/json;base64," + base64.b64encode(
                json.dumps({"version": 3, "sources": ["src/a.ts"], "sourcesContent": ["source"]}).encode()
            ).decode(),
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

    graph = extract(
        event(url="https://example.com/vendor.js", mime="text/javascript",
              body="//# sourceMappingURL=data:application/json;base64,inline"),
        artifacts, javascript_runner=runner,
    )
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


def test_svg_links_bases_scripts_and_css(event):
    from unittest.mock import MagicMock

    runner = MagicMock(return_value={"nodes": [], "edges": []})
    graph = extract(event(url="https://example.com/art/icon.svg", mime="image/svg+xml", body="""
    <s:svg xmlns:s="http://www.w3.org/2000/svg" xmlns:x="http://www.w3.org/1999/xlink"
           xml:base="/assets/" onload="fetch('/ready')">
      <s:g xml:base="nested/"><s:image href="new.png" x:href="old.png"/>
      <s:use x:href="sprite.svg#icon"/><s:use href="#local"/>
      <s:a href="/next#route"/><s:pattern href="pattern.svg"/>
      <s:script href="app.js"/><s:script><![CDATA[fetch('/inline')]]></s:script>
      <s:a href="javascript:fetch('/clicked')" onclick="fetch('/handler')"/>
      <s:style>.icon {fill: url(texture.png)}</s:style><s:path fill="url(#paint)"
          style="filter:url(filter.svg#blur)"/>
      <s:script type="application/json">{"ignored":true}</s:script></s:g>
    </s:svg>"""), javascript_runner=runner)
    urls = {node.get("url") for node in graph.nodes.values() if node["kind"] == "resource"}
    assert {
        "https://example.com/assets/nested/new.png", "https://example.com/assets/nested/sprite.svg",
        "https://example.com/next#route", "https://example.com/assets/nested/app.js",
        "https://example.com/assets/nested/pattern.svg", "https://example.com/assets/nested/texture.png",
        "https://example.com/assets/nested/filter.svg",
    } <= urls
    assert not any(url.endswith("old.png") for url in urls)
    assert runner.call_count == 4
    assert {call.args[0] for call in runner.call_args_list} == {
        "fetch('/ready')", "fetch('/inline')", "fetch('/clicked')", "fetch('/handler')",
    }
    assert graph.contexts == [{"url": graph.url, "base": graph.url, "id": graph.event["id"]}]
    assert {"NAVIGATES_TO", "LOADS", "RESOURCE_LINK"} <= kinds(graph)


def test_inline_svg_uses_html_base_and_analyzes_scripts_once(event):
    from unittest.mock import MagicMock

    runner = MagicMock(return_value={"nodes": [], "edges": []})
    graph = extract(event(body="""<html><base href="/assets/">
      <svg xml:base="icons/" onload="fetch('/ready')"><g>
        <a xlink:href="next"><text>Next</text></a><image href="icon.png"/>
        <script>fetch('/inline')</script><svg><path onclick="fetch('/nested')"/></svg>
      </g></svg></html>"""), javascript_runner=runner)
    assert runner.call_count == 3
    urls = {node.get("url") for node in graph.nodes.values()}
    assert "https://example.com/assets/icons/icon.png" in urls
    assert "https://example.com/assets/icons/next" in urls
    assert graph.contexts[0]["base"] == "https://example.com/assets/"


@pytest.mark.parametrize("body", ["<svg>", "", "<!DOCTYPE svg SYSTEM 'https://example.com/evil.dtd'><svg/>"])
def test_svg_malformed_or_external_dtd_is_passive(event, body):
    graph = extract(event(body=body, mime="image/svg"))
    assert "HOSTED_AT" in kinds(graph)
    assert not graph.analysis
    if body in {"", "<svg>"}:
        assert "Malformed SVG response" in graph.gaps


def test_svg_does_not_resolve_entities_and_rejects_non_web_links(event, tmp_path):
    secret = tmp_path / "entity.txt"
    secret.write_text("fetch('/must-not-appear')")
    sources = []
    graph = extract(event(mime="image/svg+xml", body=f"""
    <!DOCTYPE svg [<!ENTITY local SYSTEM "{secret.as_uri()}">]>
    <svg><!-- comment --><script>&local;</script><image href="data:image/png,abc"/>
    <a href="mailto:user@example.com"/><script type="module">fetch('/ok')</script></svg>
    """), javascript_runner=lambda source, filename: sources.append(source) or {"nodes": [], "edges": []})
    assert not any("must-not-appear" in source for source in sources)
    assert "fetch('/ok')" in sources
    assert not any(node.get("url", "").startswith(("data:", "mailto:")) for node in graph.nodes.values())


def test_svg_element_and_response_budgets(event, monkeypatch):
    graph = extract(event(mime="image/svg+xml", body="<svg>" + "<g/>" * 10001 + "</svg>"))
    assert len(graph.nodes) < 10  # Decorative groups do not consume the semantic projection budget.
    monkeypatch.setattr("shyhurricane.graph.extract.MAX_BYTES", 5)
    graph = extract(event(mime="image/svg+xml", body="<svg><image href='/skip'/></svg>"))
    assert "Response exceeds 40 MiB analysis limit" in graph.gaps
    assert not any(node.get("url", "").endswith("/skip") for node in graph.nodes.values())


def test_svg_analyzer_failure_preserves_links(event):
    def fail(*args):
        raise ValueError("bad script")

    graph = extract(event(mime="image/svg+xml", body="<svg onload='bad()'><image href='/image'/></svg>"),
                    javascript_runner=fail)
    assert "LOADS" in kinds(graph)
    assert "JavaScript analysis unavailable: ValueError" in graph.gaps


def test_external_script_uses_svg_document_context(graph_paths, event):
    from shyhurricane.graph.artifacts import ArtifactStore

    artifacts = ArtifactStore("db")
    svg = event(url="https://example.com/drawing.svg", mime="image/svg+xml", body="<svg><script href='/app.js'/></svg>")
    script = event(url="https://example.com/app.js", mime="text/javascript", body="fetch('/api')")
    artifacts.register(svg)
    artifacts.register(script)
    extract(svg, artifacts)
    consumers, truncated = artifacts.consuming_documents(script["data"]["url"])
    assert [item["id"] for item in consumers] == [svg["id"]]
    assert not truncated
    graph = extract(script, artifacts, javascript_runner=lambda *args: {"nodes": [], "edges": []})
    assert graph.contexts == [{"url": svg["data"]["url"], "base": svg["data"]["url"], "id": svg["id"]}]
    artifacts.close()


@pytest.mark.parametrize("inline", [False, True])
def test_svg_javascript_real_analyzer_emits_request_edges(event, javascript_runner, inline):
    body = """<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('/ready')">
    <script>fetch('/script')</script><a href="javascript:fetch('/clicked')">go</a></svg>"""
    graph = extract(event(body=f"<html>{body}</html>" if inline else body,
                          mime="text/html" if inline else "image/svg+xml"),
                    javascript_runner=javascript_runner)
    requests = [edge for edge in graph.edges.values() if edge["kind"] == "REQUESTS"]
    assert {graph.nodes[edge["target"]]["url"] for edge in requests} >= {
        "https://example.com/ready", "https://example.com/script", "https://example.com/clicked",
    }


def test_inline_svg_css_and_non_javascript_scripts(event):
    graph = extract(event(body="""<svg><style>.x {fill:url('/paint.svg')}</style>
    <script type="application/json">{}</script><script></script><use href="#local"/></svg>"""))
    assert "LOADS" in kinds(graph)
    assert not graph.analysis
    assert any(node.get("url") == "https://example.com/paint.svg" for node in graph.nodes.values())


def test_readable_source_digest_is_retained_with_operations(event):
    import hashlib
    source = "const readable = input;"
    graph = extract(
        event(url="https://example.com/app.js", body=source, mime="text/javascript"),
        javascript_runner=lambda *args: {
            "nodes": [{"id": "input", "kind": "value", "name": "input", "location": "1:0"}],
            "edges": [], "references": [],
        },
    )
    operation = next(n for n in graph.nodes.values() if n.get("name") == "input")
    assert operation["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()


@pytest.mark.parametrize("recovered", [False, True])
def test_opengrep_binding_uses_readable_graph_source(graph_paths, event, monkeypatch, recovered):
    import hashlib

    from shyhurricane.index.javascript_analysis import _finding
    from shyhurricane.investigation.engine import artifact_hash_verifier, operation_matches

    readable = "const readable = input;"
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: readable)
    mapping = json.dumps({"version": 3, "sources": ["original.js"], "sourcesContent": [readable]})
    body = ("//# sourceMappingURL=data:application/json;base64," + base64.b64encode(mapping.encode()).decode()
            if recovered else "const r=input;")
    url = "https://example.com/app.js"
    capture = event(url=url, body=body, mime="text/javascript")
    artifacts = ArtifactStore("db")
    try:
        artifacts.register(capture)
        graph = extract(capture, artifacts, javascript_runner=lambda *args: {
            "nodes": [{"id": "input", "kind": "value", "name": "input", "location": "1:0"}],
            "edges": [], "references": [],
        })
        operation = next(n for n in graph.nodes.values() if n.get("name") == "input")
        path = "original.js" if recovered else "source.js"
        finding = _finding(url, {"check_id": "rule", "path": path, "start": {"line": 1}}, recovered)
        finding.metadata["content_sha256"] = hashlib.sha256(readable.encode()).hexdigest()
        verify = artifact_hash_verifier(artifacts)
        assert operation_matches(operation, finding.metadata, url, verify)
        finding.metadata["content_sha256"] = hashlib.sha256(body.encode()).hexdigest()
        assert not operation_matches(operation, finding.metadata, url, verify)
    finally:
        artifacts.close()


@pytest.mark.parametrize("markup", [
    '<input id="field"><script>eval(document.querySelector("#field").value)</script>',
    '<textarea id="field"></textarea><script>eval(document.querySelector("#field").value)</script>',
    '<select id="field"></select><script>eval(document.querySelector("#field").value)</script>',
    '<div id="field" contenteditable>text</div><script>eval(document.querySelector("#field").textContent)</script>',
    '<button id="field"></button><script>document.querySelector("#field").addEventListener("keydown",'
    'e=>eval(e.key))</script>',
    '<form id="field"></form><script>document.querySelector("#field").addEventListener("submit",'
    'e=>eval(e.currentTarget.action))</script>',
    '<input oninput="eval(event.target.value)">',
    '<button onclick="eval(this.textContent)">go</button>',
])
def test_ui_origins_connect_captured_elements_to_sinks(event, javascript_runner, markup):
    from unittest.mock import MagicMock

    from shyhurricane.graph.links import LinkPlanner
    from shyhurricane.investigation.engine import compact_witness
    from shyhurricane.investigation.ranking import score

    graph = extract(event(body=markup), javascript_runner=javascript_runner)
    store = MagicMock()
    store.read.return_value = []
    planner = LinkPlanner(store, graph)
    assert planner.plan_slice()
    links = planner.links
    edges = list(graph.edges.values()) + list(links.values())
    sources = [node for node in graph.nodes.values() if node.get("ui_origin")]
    pending = [([source], []) for source in sources]
    result = None
    while pending:
        nodes, steps = pending.pop()
        last = nodes[-1]
        if last.get("role") == "sink":
            witness = compact_witness({"nodes": nodes, "steps": steps}) | {"relation": "flow"}
            result = score({"anchor": "operation", "connectivity": "anchored_flow",
                            "operation_ids": [last["id"]], "witnesses": [witness]})
            if result["ui_origins"]:
                break
        if len(steps) >= 16:
            continue
        for edge in edges:
            if edge["source"] == last["id"] and edge["kind"] != "CONTAINS":
                target = graph.nodes[edge["target"]]
                if target not in nodes:
                    pending.append((nodes + [target], steps + [edge]))
    assert result and result["score_contributions"]["ui_origin"] == 10
    assert result["ui_origins"][0]["location"]
    assert result["ui_origins"][0]["evidence_ids"]


def test_ui_origin_attributes_exclude_static_content(event):
    graph = extract(event(body='<div id="static">text</div><div contenteditable="false">no</div>'))
    assert not any(node.get("ui_origin") for node in graph.nodes.values())
