from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import Neo4jError

from shyhurricane.graph import links
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import Projection


def test_indexed_candidate_paging_cache_and_limits(event, monkeypatch):
    monkeypatch.setattr(links, "READ_BATCH_SIZE", 2)
    monkeypatch.setattr(links, "LINK_LIMIT", 4)
    store = MagicMock()
    pages = [
        [{"node": {"id": str(index)}} for index in range(2)],
        [{"node": {"id": str(index)}} for index in range(2, 4)],
    ]
    store.read.side_effect = pages
    graph = Projection(event())
    planner = LinkPlanner(store, graph)
    assert len(planner.candidates("module_key", "module")) == 4
    assert planner.candidates("module_key", "module") == pages[0] + pages[1]
    assert store.read.call_count == 2
    assert store.read.call_args.kwargs["after"] == "1"
    assert "Inferred link budget reached" in graph.gaps
    planner.gap()
    assert len(graph.gaps) == 1


def test_local_module_return_parameter_and_dom_links(event):
    graph = Projection(event())
    capture = graph.event["id"]
    graph.contexts = [{"id": capture, "url": graph.url}]
    page = graph.resource(graph.url)
    importer = graph.node(
        "symbol", "import", capture_id=capture, import_key="module", imported_name="send", parameter_index=0
    )
    exporter = graph.node(
        "symbol", "export", capture_id=capture, module_key="module", export_names=["send"], parameter_index=0
    )
    selector = graph.node("symbol", "selector", capture_id=capture, selector='input[name="query"]')
    element = graph.node("element", "input", capture_id=capture, field_name="query", html_id="search")
    for node in (importer, exporter, selector):
        graph.fact(page, node, "CONTAINS", "test", location=node)
    store = MagicMock()
    store.read.return_value = []
    planner = LinkPlanner(store, graph)
    result = planner.plan()
    assert any(link["source"] == importer and link["target"] == exporter for link in result.values())
    assert any(link["source"] == element and link["target"] == selector for link in result.values())
    graph.nodes[importer]["return_value"] = True
    graph.nodes[exporter]["return_value"] = True
    planner.module(graph.nodes[importer], graph.nodes[exporter], True, True)
    assert any(link["source"] == exporter and link["target"] == importer for link in result.values())
    count = len(result)
    planner.module({**graph.nodes[importer], "imported_name": "missing"}, graph.nodes[exporter], True, True)
    planner.module(
        {**graph.nodes[importer], "return_value": False, "parameter_index": None}, graph.nodes[exporter], True, True
    )
    assert len(result) == count
    planner.add(
        graph.nodes[importer],
        graph.nodes[exporter],
        {"id": "missing"},
        "js.module-link",
        source_local=True,
        target_local=True,
        proof_local=True,
    )
    assert len(result) == count


def test_external_interfaces_and_reverse_dom_links(event, monkeypatch):
    graph = Projection(event())
    capture = graph.event["id"]
    graph.contexts = [{"id": "document", "url": graph.url}]
    importer = graph.node(
        "symbol", "import", capture_id=capture, import_key="module", imported_name="send", parameter_index=0
    )
    exporter = graph.node(
        "symbol", "export", capture_id=capture, module_key="module", export_names=["send"], parameter_index=0
    )
    selector = graph.node("symbol", "selector", capture_id=capture, selector="#search")
    graph.node("element", "input", capture_id=capture, html_id="search", field_name="query")
    for node in (importer, selector):
        graph.fact(exporter, node, "CONTAINS", "test", location=node)
    planner = LinkPlanner(MagicMock(), graph)

    def candidates(field, value):
        if field == "module_key":
            node = {
                "id": "external-export",
                "_logical_id": "logical-export",
                "export_names": ["send"],
                "parameter_index": 0,
            }
        elif field == "import_key":
            node = {"id": "external-import", "capture_id": "script", "imported_name": "send", "parameter_index": 0}
        elif field == "capture_id":
            node = {"id": "external-element", "kind": "element", "html_id": "search", "capture_id": "document"}
        else:
            node = {"id": "external-selector", "selector": value, "capture_id": "script"}
        return [{"node": node, "evidence_id": "external-proof", "contexts": [capture]}]

    monkeypatch.setattr(planner, "candidates", candidates)
    assert len(planner.plan()) >= 4
    monkeypatch.setattr(links, "LINK_LIMIT", 1)
    planner.add(
        graph.nodes[importer],
        graph.nodes[exporter],
        graph.nodes[importer],
        "js.module-link",
        source_local=True,
        target_local=True,
        proof_local=True,
    )
    assert "Inferred link budget reached" in graph.gaps


def test_link_candidate_memory_budget_subdivides_reads_and_keeps_paging(event, monkeypatch):
    from shyhurricane.graph.publication import PublicationMemoryError

    monkeypatch.setattr(links, "READ_BATCH_SIZE", 2)
    store = MagicMock()

    def read(statement, **parameters):
        if parameters["limit"] > 1:
            raise Neo4jError._hydrate_neo4j(
                code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget"
            )
        return [{"node": {"id": key}} for key in ("a", "b", "c") if key > parameters["after"]][:1]

    store.read.side_effect = read
    planner = LinkPlanner(store, Projection(event()))
    assert [row["node"]["id"] for row in planner.candidates("module_key", "module")] == ["a", "b", "c"]
    store.read.side_effect = Neo4jError._hydrate_neo4j(
        code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget"
    )
    with pytest.raises(PublicationMemoryError):
        planner.candidates("import_key", "module")
    store.read.side_effect = Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
    with pytest.raises(Neo4jError):
        planner.candidates("selector", "#test")
