import base64
import hashlib
import json

import pytest

from shyhurricane.graph.artifacts import ArtifactStore, recovered_sources
from shyhurricane.graph.model import Projection, capture_event, identity, web_url
from shyhurricane.index import javascript_analysis


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://EXAMPLE.com:443/a?b=2&a=1#x", "https://example.com/a?b=2&a=1"),
        ("http://[::1]:8080/a", "http://[::1]:8080/a"),
        ("wss://example.com:443/ws", "wss://example.com/ws"),
        ("javascript:alert(1)", None),
        ("https://user:pass@example.com", None),
        ("https://x:bad/", None),
    ],
)
def test_web_urls(url, expected):
    assert web_url(url) == expected


def test_capture_and_evidence_identity(event):
    first = event(body="one")
    assert first == event(body="one")
    assert first["id"] != event(body="two")["id"]
    assert capture_event({"timestamp": "bad"})["timestamp_inferred"]
    assert not capture_event({"timestamp": "2026-01-01"})["timestamp_inferred"]
    graph = Projection(first)
    a, b = graph.resource(graph.url), graph.resource(graph.url, "POST")
    assert a != b
    edge = graph.fact(a, b, "SUBMITS_TO", "test", classification="observed", snippet="x" * 2000)
    graph.fact(a, b, "SUBMITS_TO", "test", classification="observed", snippet="x" * 2000)
    assert len(graph.edges) == 1
    assert len(graph.evidence[graph.edges[edge]["evidence_id"]]["snippet"]) == 1000
    assert web_url("#route", graph.url, fragment=True).endswith("#route")


def test_artifacts_survive_reopen_and_reconcile(graph_paths, event):
    cache = ArtifactStore("db")
    first = event()
    cache.register(first)
    cache.register(first)
    cache.references(first["id"], ["https://example.com/app.js"] * 2)
    assert cache.dependents("https://example.com/app.js") == [first]
    assert cache.latest("missing") is None
    assert cache.cached("key", lambda: {"a": 1}) == {"a": 1}
    cache.close()
    cache = ArtifactStore("db")
    assert cache.latest(first["data"]["url"]) == first
    assert cache.cached("key", lambda: pytest.fail("should reuse cache")) == {"a": 1}
    cache.status(first["id"], "failed", "bad")
    assert cache.counts() == {"failed": 1}
    assert cache.deobfuscate("source", lambda s: s.upper()) == "SOURCE"
    cache.close()


def test_source_map_cache_shares_fetch_with_normalized_scanner(graph_paths, event, monkeypatch):
    cache = ArtifactStore("db")
    source_map = json.dumps({"version": 3, "sources": ["src.js"], "sourcesContent": ["eval(x)"]})
    calls = []
    monkeypatch.setattr(javascript_analysis, "_fetch_map", lambda *args: calls.append(args) or source_map)
    assert cache.source_map("https://example.com/not-js", "x", {}, True) is None
    assert cache.source_map("https://example.com/app.js", "raw", {}, False) is None
    assert cache.source_map("https://example.com/app.js", "raw", {}, True) == source_map
    digest = hashlib.sha256(b"raw").hexdigest()
    assert cache.source_map("https://example.com/app.js", "normalized", {}, True, original_hash=digest) == source_map
    assert len(calls) == 1
    cache.register(event(url="https://example.com/app.js.map", body=source_map, mime="application/json"))
    assert cache.source_map("https://example.com/app.js", "other", {}, False) == source_map
    cache.close()


def test_negative_map_cache_and_safe_recovery(graph_paths, monkeypatch):
    cache = ArtifactStore("db")
    calls = []
    monkeypatch.setattr(javascript_analysis, "_fetch_map", lambda *args: calls.append(args) or "bad")
    assert cache.source_map("https://example.com/app.js", "raw", {}, True) is None
    assert cache.source_map("https://example.com/app.js", "raw", {}, True) is None
    assert len(calls) == 1
    content = json.dumps({"sections": [{"map": {"sources": ["../../escape.js"], "sourcesContent": ["source"]}}]})
    assert recovered_sources(content) == [("../../escape.js", "source")]
    assert not (graph_paths / "escape.js").exists()
    assert identity("one") != identity("two")
    cache.close()


def test_inline_and_explicit_map_hints_never_fetch(graph_paths, event, monkeypatch):
    cache = ArtifactStore("db")
    mapping = json.dumps({"version": 3, "sources": ["a.js"], "sourcesContent": ["source"]})
    encoded = base64.b64encode(mapping.encode()).decode()
    monkeypatch.setattr(javascript_analysis, "_fetch_map", lambda *args: pytest.fail("network"))
    inline = f"source\n//# sourceMappingURL=data:application/json;base64,{encoded}"
    assert cache.source_map("https://example.com/a.js", inline, {}, False) == mapping
    cache.register(event(url="https://example.com/explicit.map", body=mapping))
    assert (
        cache.source_map(
            "https://example.com/a.js", "source", {}, False, response_headers={"SourceMap": "explicit.map"}
        )
        == mapping
    )
    assert cache.source_map("https://example.com/a.js", "//# sourceMappingURL=missing.map", {}, False) is None
    assert (
        cache.source_map("https://example.com/a.js", "//# sourceMappingURL=data:application/json;base64,bad", {}, False)
        is None
    )
    assert (
        cache.source_map("https://example.com/a.js", "//# sourceMappingURL=data:application/json,%7B%7D", {}, False)
        is None
    )
    original = event(url="https://example.com/a.js", body=inline)
    cache.register(original)
    assert (
        cache.source_map(
            "https://example.com/a.js",
            "normalized",
            {},
            False,
            original_hash=hashlib.sha256(inline.encode()).hexdigest(),
        )
        == mapping
    )
    cache.close()


def test_capture_budgets_report_incompleteness_without_dangling_edges(event, monkeypatch):
    monkeypatch.setattr("shyhurricane.graph.model.MAX_GRAPH_NODES", 2)
    monkeypatch.setattr("shyhurricane.graph.model.MAX_GRAPH_EDGES", 1)
    graph = Projection(event())
    a, b, c = graph.node("field", "a"), graph.node("field", "b"), graph.node("field", "c")
    assert not graph.fact(a, c, "FLOWS_TO", "test")
    assert graph.fact(a, b, "FLOWS_TO", "test")
    assert not graph.fact(b, a, "FLOWS_TO", "test")
    assert len(graph.gaps) == 2


def test_lazy_dependency_contexts_are_bounded_and_handle_cycles(graph_paths, event):
    cache = ArtifactStore("db")
    page = event(body='<script src="/entry.js"></script>')
    entry = event(url="https://example.com/entry.js", mime="text/javascript")
    chunk = event(url="https://example.com/chunk.js", mime="text/javascript")
    for capture in (page, entry, chunk):
        cache.register(capture)
    cache.references(page["id"], [entry["data"]["url"]])
    cache.references(entry["id"], [chunk["data"]["url"]])
    cache.references(chunk["id"], [entry["data"]["url"]])
    documents, truncated = cache.consuming_documents(chunk["data"]["url"])
    assert documents == [page] and not truncated
    assert cache.consuming_documents(chunk["data"]["url"], budget=1)[1]
    cache.close()
