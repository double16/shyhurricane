"""Discovery coverage survives materialization bounds and supports explicit continuation and expansion."""

import json
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import cursors
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.cursors import QueryCursors
from shyhurricane.graph.discovery_manifest import archive_ir
from shyhurricane.graph.epoch_catalog import affected_captures
from shyhurricane.graph.extract import extract
from shyhurricane.graph.manifest_query import expand_analysis, manifest_query
from shyhurricane.graph.markup import scan_markup, scan_svg
from shyhurricane.graph.model import Projection


def test_late_markup_facts_survive_decorations_and_detail_limit(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(body="<div>text</div>" * 12000 +
                                      '<form action="/save"><input name="secret"></form><script src="/tail.js"></script>'))
    graph = extract(capture, artifacts)
    assert any(node.get("url") == "https://example.com/save" for node in graph.nodes.values())
    resources, _ = artifacts.manifest.page("example.com", kind="resource")
    assert {"https://example.com/save", "https://example.com/tail.js"} <= {row["url"] for row in resources}
    facts = []
    markup, deferred = scan_markup('<input name="first"><input name="last">', facts.append, maximum=1)
    assert deferred == 1 and len(facts) == 2 and "last" not in markup
    artifacts.close()


def test_normalized_memberships_keep_current_and_obsolete_contexts(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "fixture", discovery="complete", flow="complete")
    first = artifacts.manifest.fact(unit, capture["id"], "field", {"url": capture["data"]["url"], "name": "value"},
                                    contexts=["old"])
    second = artifacts.manifest.fact(unit, capture["id"], "field", {"url": capture["data"]["url"], "name": "value"},
                                     contexts=["current"])
    assert first == second
    assert artifacts.connection.execute("SELECT count(*) FROM graph_manifest_contexts").fetchone()[0] == 2
    with pytest.raises(ValueError):
        artifacts.manifest.unit(capture["id"], "bad", flow="unknown")
    with pytest.raises(ValueError):
        artifacts.manifest.page("example.com", limit=1001)
    artifacts.close()


def test_paged_inventory_reaches_every_fact_without_neo4j(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "fixture", discovery="complete", flow="partial")
    for i in range(60):
        artifacts.manifest.fact(unit, capture["id"], "resource", {
            "id": str(i), "url": f"https://example.com/{i}", "method": "GET",
        })
    page = manifest_query(artifacts, "example.com", kind="resource", limit=7)
    selected = {row["id"] for row in page["results"]}
    while page["continuation_token"]:
        from shyhurricane.graph.query import GraphQuery
        page = GraphQuery(MagicMock(), artifacts=artifacts).continue_query(page["continuation_token"], limit=7)
        selected.update(row["id"] for row in page["results"])
    assert {str(i) for i in range(60)} <= selected
    assert page["coverage"]["flow"] in {"pending", "partial"}
    artifacts.close()


def test_archived_ir_shards_are_addressable_and_expansion_is_offline(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url="https://example.com/app.js", mime="text/javascript"))
    raw = {"nodes": [{"id": "source", "kind": "symbol", "role": "source"},
                     {"id": "sink", "kind": "call", "role": "sink"}],
           "edges": [{"source": "source", "target": "sink", "kind": "FLOWS_TO"}],
           "references": [{"url": "./dependency.js", "kind": "IMPORTS"}], "gaps": []}
    unit = archive_ir(artifacts, capture, capture["data"]["url"], "app.js", raw)
    shards = artifacts.connection.execute(
        "SELECT id,artifact FROM graph_manifest_units WHERE source_path LIKE '%#flow-shard=%'"
    ).fetchall()
    assert len(shards) == 1
    assert artifacts.read(shards[0][1])["edges"] == raw["edges"]
    queue = MagicMock()
    result = expand_analysis(artifacts, queue, "example.com", capture["id"], shards[0][0])
    assert result["status"] == "pending" and queue.put.call_args.args[0]["offline_analysis"]
    assert queue.put.call_args.args[0]["analysis_unit_id"] == shards[0][0]
    from shyhurricane.graph.expansion import Expansions

    assert Expansions(artifacts, MagicMock()).accept(queue.put.call_args.args[0], 1) == result["work_id"]
    with pytest.raises(ValueError):
        expand_analysis(artifacts, queue, "target.local", capture["id"], unit)
    with pytest.raises(ValueError):
        expand_analysis(artifacts, queue, "example.com", capture["id"], "missing")
    artifacts.close()


def test_dependency_membership_does_not_follow_navigation(graph_paths, event):
    artifacts = ArtifactStore("db")
    page = artifacts.register(event())
    script = artifacts.register(event(url="https://example.com/app.js"))
    other = artifacts.register(event(url="https://example.com/other"))
    artifacts.manifest.dependency(page["id"], script["data"]["url"], "LOADS")
    artifacts.manifest.dependency(page["id"], other["data"]["url"], "NAVIGATES_TO")
    watermark = artifacts.connection.execute("SELECT max(rowid) FROM captures").fetchone()[0]
    assert set(affected_captures(artifacts.connection, [page["id"]], watermark)) == {page["id"], script["id"]}
    artifacts.manifest.dependency(other["id"], script["data"]["url"], "LOADS")
    assert set(affected_captures(artifacts.connection, [page["id"]], watermark)) == {page["id"], script["id"]}
    assert set(affected_captures(artifacts.connection, [script["id"]], watermark)) == {
        page["id"], script["id"], other["id"],
    }
    artifacts.close()


def test_cursor_expiry_capacity_and_size_are_explicit(tmp_path, monkeypatch):
    store = QueryCursors(tmp_path)
    token = store.save({"test": True})
    assert store.load(token)[0] == {"test": True}
    with pytest.raises(ValueError):
        store.load("invalid")
    with pytest.raises(ValueError):
        store.load("x" * 43)
    monkeypatch.setattr(cursors, "MAX_ACTIVE", 1)
    with pytest.raises(ValueError, match="Too many"):
        store.save({})
    store.remove(token)
    monkeypatch.setattr(cursors, "MAX_STATE_BYTES", 2)
    with pytest.raises(ValueError, match="budget"):
        store.save({"too": "large"})
    monkeypatch.setattr(cursors, "MAX_STATE_BYTES", 100)
    token = store.save({}, expires=0)
    with pytest.raises(ValueError, match="expired"):
        store.load(token)
    store.save({})
    store.close()


def test_fact_payload_limit_keeps_blob_and_reference(graph_paths, event, monkeypatch):
    from shyhurricane.graph import manifest

    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "oversized")
    monkeypatch.setattr(manifest, "PAGE_BYTES", 100)
    key = artifacts.manifest.fact(unit, capture["id"], "field", {
        "url": "https://example.com/", "name": "x" * 200,
    })
    payload = artifacts.read(artifacts.connection.execute(
        "SELECT data FROM graph_manifest_facts WHERE id=?", (key,)
    ).fetchone()[0])
    assert artifacts.read(payload["artifact"])["name"] == "x" * 200
    records, _ = artifacts.manifest.page("example.com", kind="field")
    assert records[0]["oversized"]
    artifacts.close()


def test_svg_stream_retains_qualified_bases_and_does_not_expand_entities():
    records = []
    body, deferred = scan_svg('<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:g xml:base="/assets/">'
                              '<s:script>fetch("/ok")</s:script><s:image href="icon.svg"/></s:g></s:svg>',
                              records.append)
    assert "xml:base" in body and "fetch" in body and not deferred
    assert len(records) == 4
    body, deferred = scan_svg('<svg><image href="a"/><image href="b"/></svg>', maximum=1)
    assert deferred == 2


def test_repeated_fact_edges_keep_both_document_versions(event):
    graph = Projection(event())
    source, target = graph.resource("https://example.com/a"), graph.resource("https://example.com/b")
    for context in ["old", "current"]:
        graph.fact(source, target, "REQUESTS", "test", context_capture_id=context)
    assert len(graph.edges) == 2
    assert {edge["context_capture_id"] for edge in graph.edges.values()} == {"old", "current"}


def test_inventory_filters_precede_paging_and_continuations_freeze_versions(graph_paths, event):
    from shyhurricane.graph.query import GraphQuery

    artifacts = ArtifactStore("db")
    old = artifacts.register(event(body="old"))
    unit = artifacts.manifest.unit(old["id"], "fixture", discovery="complete", flow="complete")
    for index in range(12):
        artifacts.manifest.fact(unit, old["id"], "resource", {
            "id": str(index), "url": f"https://example.com/api/{index}", "method": "POST",
        })
    first = manifest_query(artifacts, "example.com", kind="resource", method="POST", limit=3)
    query = GraphQuery(MagicMock(), artifacts=artifacts)
    artifacts.register(event(body="new", timestamp="2026-02-01T00:00:00Z"))
    token = first["continuation_token"]
    second = query.continue_query(token, limit=3)
    assert query.continue_query(token, limit=3) == second
    selected = {record["id"] for record in first["results"] + second["results"]}
    while second["continuation_token"]:
        second = query.continue_query(second["continuation_token"], limit=3)
        selected.update(record["id"] for record in second["results"])
    assert selected == {str(index) for index in range(12)}
    assert not manifest_query(artifacts, "example.com", method="POST")["results"]
    assert len(manifest_query(artifacts, "example.com", method="POST", historical=True)["results"]) == 12
    assert len(manifest_query(artifacts, "example.com", method="POST", as_of=old["observed_at"])["results"]) == 12
    assert len(manifest_query(artifacts, "example.com", historical=True,
                              url="https://example.com/api/11")["results"]) == 1
    assert artifacts.latest(old["data"]["url"], as_of=old["observed_at"])["id"] == old["id"]
    artifacts.close()


def test_coverage_is_scope_specific_and_isolated_nodes_have_detail_units(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    other = artifacts.register(event(url="https://target.local/"))
    artifacts.manifest.unit(other["id"], "failed", discovery="failed", flow="failed")
    artifacts.manifest.unit(capture["id"], "capture:" + capture["data"]["url"],
                            discovery="complete", flow="complete")
    archive_ir(artifacts, capture, capture["data"]["url"], "app.js", {
        "nodes": [{"id": "alone", "role": "sink", "kind": "call"}], "edges": [],
    }, contexts=[{"id": "current", "url": "https://example.com/"},
                 {"id": "obsolete", "url": "https://example.com/"}])
    assert artifacts.manifest.coverage(scope="example.com")["flow"] == "complete"
    assert artifacts.manifest.coverage(scope="target.local")["flow"] == "failed"
    assert artifacts.connection.execute(
        "SELECT count(*) FROM graph_manifest_units WHERE source_path LIKE '%#node-shard=%'"
    ).fetchone()[0] == 1
    assert artifacts.connection.execute("SELECT count(*) FROM graph_unit_contexts").fetchone()[0] == 2
    artifacts.close()


def test_discovery_batch_retains_committed_chunks_and_rolls_back_failed_tail(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "fixture")
    with pytest.raises(RuntimeError):
        with artifacts.manifest.batch():
            for index in range(501):
                artifacts.manifest.fact(unit, capture["id"], "field", {"name": str(index), "url": "https://example.com/"})
            raise RuntimeError("killed")
    count = artifacts.connection.execute("SELECT count(*) FROM graph_manifest_facts WHERE unit_id=? AND kind='field'", (unit,)).fetchone()[0]
    assert count == 500
    assert not artifacts.manifest.batching
    artifacts.close()


def test_deferred_inline_script_is_retained_in_html_and_svg(graph_paths, event):
    from shyhurricane.graph.discovery_manifest import markup_emitter

    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    emit = markup_emitter(artifacts, capture, capture["data"]["url"])
    body, count = scan_markup('<input name="first"><script>eval(location.hash)</script>', emit, maximum=1)
    assert count == 1 and "eval" not in body
    svg = artifacts.register(event(url="https://example.com/image.svg", mime="image/svg+xml"))
    emit_svg = markup_emitter(artifacts, svg, svg["data"]["url"])
    body, count = scan_svg('<svg><script>fetch("/tail")</script></svg>', emit_svg, maximum=1)
    assert count == 1 and "fetch" not in body
    rows = artifacts.connection.execute(
        "SELECT artifact,discovery FROM graph_manifest_units WHERE source_path LIKE '%#deferred-script=%'"
    ).fetchall()
    assert len(rows) == 2 and all(row[1] == "pending" for row in rows)
    assert all("source" in artifacts.read(row[0]) for row in rows)
    artifacts.close()


def test_path_continuation_advances_frontier_and_replays_at_same_revision(graph_paths, event, monkeypatch):
    from collections import defaultdict

    from shyhurricane.graph import query
    from shyhurricane.graph.query import GraphQuery

    artifacts = ArtifactStore("db")
    artifacts.register(event())
    revisions = []

    class Snapshot:
        def __init__(self, *args, **kwargs):
            self.parameters = {"revision": 7}
            self.read_cache, self.memberships, self.association_edges = {}, {}, {}
            self.selected_memberships, self.associated = set(), set()
            self.stopped = False
            self.nodes = {key: {"id": key, "kind": "symbol", "url": "https://example.com/", "role": role}
                          for key, role in [("a", "source"), ("b", ""), ("c", "sink")]}
            self.storage, self.resolved, self.probes = defaultdict(set), set(), {}
            self.metadata = {"retrieval_truncated": False, "truncation_reasons": [], "analysis_gaps": [],
                             "instructions": "static evidence", "analysis_summaries": []}
            self.adjacent = {
                "a": [{"id": "ab", "source": "a", "target": "b", "kind": "FLOWS_TO"}],
                "b": [{"id": "bc", "source": "b", "target": "c", "kind": "FLOWS_TO"}],
            }

        def select(self, value, *args, **kwargs):
            return [value]

        def expand(self, *args, **kwargs):
            revisions.append(self.parameters["revision"])

        def finish(self, count):
            revisions.append(self.parameters["revision"])

    monkeypatch.setattr("shyhurricane.graph.traversal.TraversalSnapshot", Snapshot)
    monkeypatch.setattr(query, "MAX_ENTITIES", 1)
    service = GraphQuery(MagicMock(), artifacts=artifacts)
    service.pin_query = MagicMock()
    first = service.paths("example.com", "a", end="c", mode="flow")
    assert first["continuation_token"] and not first["results"]
    second = service.continue_query(first["continuation_token"])
    assert second["continuation_token"] and not second["results"]
    final = service.continue_query(second["continuation_token"])
    assert [node["id"] for node in final["results"][0]["nodes"]] == ["a", "b", "c"]
    assert service.continue_query(second["continuation_token"]) == final
    assert revisions and set(revisions) == {7}
    unavailable = GraphQuery(MagicMock())
    with pytest.raises(ValueError, match="unavailable"):
        unavailable.continue_query("x" * 43)
    cursors = QueryCursors(artifacts.root)
    token = cursors.save({"operation": "unsupported"})
    cursors.close()
    with pytest.raises(ValueError, match="Unsupported"):
        service.continue_query(token)
    artifacts.close()


def test_manifest_element_selection_uses_persisted_contexts_and_bounds(graph_paths, event, monkeypatch):
    from shyhurricane.graph import manifest
    from shyhurricane.graph.query import GraphQuery

    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url="https://example.com/app.js"))
    document = artifacts.register(event(url="https://example.com/document"))
    unit = artifacts.manifest.unit(capture["id"], "fixture")
    for index in range(4):
        artifacts.manifest.fact(unit, capture["id"], "symbol", {
            "id": str(index), "url": "https://example.com/app.js", "role": "source", "name": "value" * 20,
        }, contexts=[document["id"]])
    service = GraphQuery(MagicMock(), artifacts=artifacts)
    result = service.elements("example.com", role="source", kinds=["symbol"],
                              context_url="https://example.com/document")
    assert len(result["results"]) == 4
    assert not service.elements("example.com", kinds=["cookie"])["results"]
    monkeypatch.setattr(manifest, "PAGE_BYTES", 250)
    rows, cursor = artifacts.manifest.page("example.com", kind="symbol")
    assert len(rows) == 1 and cursor
    assert not artifacts.manifest.page("https://example.com/other", kind="symbol")[0]
    with pytest.raises(ValueError):
        manifest_query(artifacts, "example.com", limit=0)
    artifacts.close()


def test_cursor_global_storage_and_retained_count_are_bounded(tmp_path, monkeypatch):
    store = QueryCursors(tmp_path)
    monkeypatch.setattr(cursors, "MAX_RETAINED", 1)
    token = store.save({"state": True})
    store.complete(token, {"result": True})
    with pytest.raises(ValueError, match="storage budget"):
        store.save({})
    monkeypatch.setattr(cursors, "MAX_STORE_BYTES", 1)
    with pytest.raises(ValueError, match="storage budget"):
        store.complete(token, {"result": True})
    store.remove(token)
    with pytest.raises(ValueError, match="storage budget"):
        store.save({"large": True})
    store.close()


def test_external_script_inventory_uses_current_document_membership_without_fact_fanout(graph_paths, event):
    from shyhurricane.graph.query import GraphQuery

    artifacts = ArtifactStore("db")
    old = artifacts.register(event(url="https://example.com/document", body="old"))
    script = artifacts.register(event(url="https://cdn.target.local/app.js", mime="text/javascript"))
    raw = {"nodes": [{"id": str(index), "kind": "symbol", "role": "source"} for index in range(50)],
           "edges": []}
    archive_ir(artifacts, script, script["data"]["url"], script["data"]["url"], raw,
               contexts=[{"id": old["id"], "url": old["data"]["url"], "base": old["data"]["url"]}])
    query = GraphQuery(MagicMock(), artifacts=artifacts)
    assert len(query.elements("https://example.com/document", role="source")["results"]) == 50
    assert artifacts.connection.execute("SELECT count(*) FROM graph_unit_contexts").fetchone()[0] == 1
    assert artifacts.connection.execute("SELECT count(*) FROM graph_manifest_contexts").fetchone()[0] == 0
    artifacts.register(event(url=old["data"]["url"], body="new", timestamp="2026-02-01T00:00:00Z"))
    assert not query.elements("example.com", role="source")["results"]
    assert len(query.elements("example.com", role="source", historical=True)["results"]) == 50
    assert len(query.elements("example.com", role="source", as_of=old["observed_at"])["results"]) == 50
    artifacts.close()


def test_deferred_markup_shard_keeps_ancestry_and_reuses_discovered_node_ids(graph_paths, event):
    artifacts = ArtifactStore("db")
    body = '<base href="/assets/"><form id="owner" method="POST" action="save"><fieldset disabled>'
    body += '<input name="padding">' * 10010
    body += '<input id="tail" name="important"></fieldset></form>'
    capture = artifacts.register(event(body=body))
    extract(capture, artifacts)
    discovered = next(
        payload for (reference,) in artifacts.connection.execute(
            "SELECT data FROM graph_manifest_facts WHERE kind='field'"
        ) if (payload := artifacts.read(reference)).get("attributes", {}).get("id") == "tail"
    )
    detail = extract(capture, markup_offset=10000, markup_limit=1000, record_discovery=False)
    assert discovered["id"] in detail.nodes
    assert not detail.nodes[discovered["id"]]["form_successful"]
    assert any(node.get("url") == "https://example.com/assets/save" and node.get("method") == "POST"
               for node in detail.nodes.values())
    assert len(detail.nodes) < 1000
    units = manifest_query(artifacts, "example.com", kind="analysis_unit")["results"]
    assert any(row["source_path"].endswith("#markup-shard=10") for row in units)
    artifacts.close()


def test_svg_window_keeps_namespaced_ancestry_and_stable_semantic_identity(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(mime="image/svg+xml", body=(
        '<svg xmlns="http://www.w3.org/2000/svg"><g xml:base="/assets/">'
        '<image id="one" href="one.png"/><image id="tail" href="tail.png"/></g></svg>'
    )))
    whole = extract(capture, artifacts)
    detail = extract(capture, markup_offset=3, markup_limit=1, record_discovery=False)
    node = next(node for node in whole.nodes.values() if node.get("html_id") == "tail")
    assert node["id"] in detail.nodes
    assert any(node.get("url") == "https://example.com/assets/tail.png" for node in detail.nodes.values())
    artifacts.close()


def test_future_and_unverified_source_maps_cannot_replace_delivered_code(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    monkeypatch.setattr(artifacts, "deobfuscate", lambda body, function: body)
    bundle = artifacts.register(event(url="https://example.com/app.js", mime="text/javascript", body="safe();"))
    mapping = json.dumps({"version": 3, "sources": ["app.js"], "sourcesContent": ["eval(location.hash)"]})
    future = artifacts.register(event(url="https://example.com/app.js.map", mime="application/json", body=mapping,
                                      timestamp="2026-02-01T00:00:00Z"))
    calls = []

    def runner(source, filename):
        calls.append(source)
        return {"nodes": [], "edges": [], "references": []}

    graph = extract(bundle, artifacts, javascript_runner=runner)
    assert calls == ["safe();"] and not graph.candidate_sources
    standalone = extract(future, artifacts, javascript_runner=runner)
    assert calls == ["safe();"] and standalone.candidate_sources[0]["association"] == "unverified_standalone"
    earlier = artifacts.register(event(url=future["data"]["url"], mime="application/json", body=mapping))
    graph = extract(bundle, artifacts, javascript_runner=runner)
    assert graph.candidate_sources[0]["association"] == "unverified_external"
    assert calls == ["safe();"]  # Cached delivered-code IR is reused.
    artifacts.manifest.unit(earlier["id"], "capture:" + earlier["data"]["url"], discovery="failed", flow="failed")
    assert artifacts.manifest.coverage(scope="example.com")["flow"] != "failed"
    assert artifacts.manifest.coverage(scope="example.com", historical=True)["flow"] == "failed"
    artifacts.close()


def test_duplicate_heavy_manifest_page_resumes_before_unconsumed_records(tmp_path):
    from types import SimpleNamespace

    manifest = MagicMock()
    manifest.watermark.return_value = {"facts": 6}
    manifest.coverage.return_value = {"discovery": "complete", "flow": "complete"}
    manifest.page.side_effect = [
        ([{"id": "seen", "manifest_id": "1"}, {"id": "seen", "manifest_id": "2"},
          {"id": "first", "manifest_id": "3"}], "3"),
        ([{"id": "second", "manifest_id": "4"}, {"id": "third", "manifest_id": "5"},
          {"id": "fourth", "manifest_id": "6"}], None),
    ]
    result = manifest_query(SimpleNamespace(root=tmp_path, manifest=manifest, budget=None), "example.com", seen=["seen"], limit=3)
    assert [row["id"] for row in result["results"]] == ["first", "second", "third"]
    store = QueryCursors(tmp_path)
    state, _ = store.load(result["continuation_token"])
    assert state["after"] == "5"
    store.close()


@pytest.mark.parametrize("declared_first", [False, True])
def test_markup_window_preserves_explicit_form_owners_outside_the_window(event, declared_first):
    form = '<form id="owner" action="/save" method="POST"></form>'
    control = '<input name="value" form="owner"><input name="ignored" form="missing">'
    body = form + control if declared_first else control + form
    graph = extract(event(body=body), markup_offset=1 if declared_first else 0,
                    markup_limit=2, record_discovery=False)
    field = next(node for node in graph.nodes.values() if node.get("field_name") == "value")
    assert field["form_selectors"] == ["#owner"]
    assert any(node.get("url") == "https://example.com/save" and node.get("method") == "POST"
               for node in graph.nodes.values())
    ignored = next(node for node in graph.nodes.values() if node.get("field_name") == "ignored")
    assert ignored["form_selectors"] == []
