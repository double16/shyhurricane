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
    def read(statement, **parameters):
        if "ids" in parameters:
            return [{"node": {"id": key}} for key in parameters["ids"]]
        return [{"id": row["node"]["id"]} for row in pages.pop(0)]

    store.read.side_effect = read
    graph = Projection(event())
    planner = LinkPlanner(store, graph)
    assert len(planner.candidates("module_key", "module")) == 4
    assert [row["node"]["id"] for row in planner.candidates("module_key", "module")] == ["0", "1", "2", "3"]
    assert store.read.call_count == 4
    assert store.read.call_args_list[2].kwargs["after"] == "1"
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
        if "ids" in parameters:
            return [{"node": {"id": key}} for key in parameters["ids"]]
        if parameters["limit"] > 1:
            raise Neo4jError._hydrate_neo4j(
                code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget"
            )
        return [{"id": key} for key in ("a", "b", "c") if key > parameters["after"]][:1]

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


@pytest.mark.parametrize("returns", [False, True])
def test_reexport_interfaces_forward_local_and_external_proofs(event, returns):
    graph = Projection(event())
    capture = graph.event["id"]
    page = graph.resource(graph.url)
    importer = graph.node(
        "parameter",
        "caller",
        capture_id=capture,
        import_key="barrel",
        imported_name="load",
        parameter_index=None if returns else 0,
        return_value=returns,
    )
    barrel = graph.node(
        "symbol",
        "barrel",
        capture_id=capture,
        module_key="barrel",
        export_names=["load"],
        imported_name="read",
        reexport_name="load",
        import_key="api",
    )
    actual = graph.node(
        "parameter",
        "actual",
        capture_id=capture,
        module_key="api",
        export_names=["read"],
        parameter_index=None if returns else 0,
        return_value=returns,
    )
    for node in (importer, barrel, actual):
        graph.fact(page, node, "CONTAINS", "test", location=node)
    store = MagicMock()
    store.read.return_value = []
    planner = LinkPlanner(store, graph)
    result = planner.plan()
    proxies = [node for node in graph.nodes.values() if node["kind"] == "module_interface"]
    assert len(proxies) == 1
    proxy = proxies[0]["id"]
    expected = [(actual, proxy), (proxy, importer)] if returns else [(importer, proxy), (proxy, actual)]
    assert all(
        any(edge["source"] == start and edge["target"] == end for edge in result.values()) for start, end in expected
    )
    assert all(edge["_proof_local"] for edge in result.values())
    # A retained external barrel keeps its own proof, without rewriting it into this publication.
    external = {**graph.nodes[barrel], "id": "external", "evidence_id": "external-proof"}
    planner.module(graph.nodes[importer], external, True, False)
    external_proxy = next(
        node for node in graph.nodes.values() if node["kind"] == "module_interface" and node["id"] != proxy
    )
    proof_edge = next(
        edge
        for edge in result.values()
        if external_proxy["id"] in {edge["source"], edge["target"]} and actual in {edge["source"], edge["target"]}
    )
    assert proof_edge["evidence_id"] == "external-proof" and not proof_edge["_proof_local"]


def test_reexport_cycles_missing_targets_and_budgets_are_bounded(event, monkeypatch):
    graph = Projection(event())
    page = graph.resource(graph.url)
    caller = graph.node("parameter", "caller", capture_id=graph.event["id"], imported_name="read", parameter_index=0)
    barrel = graph.node(
        "symbol",
        "barrel",
        capture_id=graph.event["id"],
        module_key="api",
        export_names=["read"],
        import_key="api",
        imported_name="read",
        reexport_name="read",
    )
    for node in (caller, barrel):
        graph.fact(page, node, "CONTAINS", "test")
    store = MagicMock()
    store.read.return_value = []
    planner = LinkPlanner(store, graph)
    planner.module(graph.nodes[caller], graph.nodes[barrel], True, True)
    assert len(planner.links) == 1
    planner.module(
        graph.nodes[caller], graph.nodes[barrel], True, True, seen={(str(index), 0, False) for index in range(32)}
    )
    assert "Inferred link budget reached" in graph.gaps
    graph.nodes[barrel]["import_key"] = "missing"
    planner.module(graph.nodes[caller], graph.nodes[barrel], True, True)
    assert any("Unresolved re-export" in gap for gap in graph.gaps)
    planner.module({**graph.nodes[caller], "parameter_index": None}, graph.nodes[barrel], True, True)
    graph.node_limit = len(graph.nodes)
    alternate = {**graph.nodes[barrel], "id": "new-barrel"}
    planner.module(graph.nodes[caller], alternate, True, True)
    assert "Capture entity budget reached" in graph.gaps


def test_form_links_require_ownership_field_and_context(event):
    graph = Projection(event())
    capture = graph.event["id"]
    page = graph.resource(graph.url)
    read = graph.node("result", "read", capture_id=capture, selector="#form", form_data=True, form_field="name")
    request = graph.node("call", "request", capture_id=capture, selector="#form", form_request=True)
    graph.fact(page, read, "CONTAINS", "test")
    graph.fact(page, request, "CONTAINS", "test")
    planner = LinkPlanner(MagicMock(), graph)
    control = {
        "id": "input",
        "capture_id": "document",
        "html_tag": "input",
        "field_name": "name",
        "form_selectors": ["#form"],
    }
    planner.dom(graph.nodes[read], control, True, False, ["document"])
    assert len(planner.links) == 1
    for changes in (
        {"disabled": True},
        {"field_name": "secret"},
        {"field_name": None},
        {"html_tag": "button"},
        {"form_selectors": ["#other"]},
        {"capture_id": "other"},
    ):
        planner.dom(graph.nodes[read], control | changes, True, False, ["document"])
    assert len(planner.links) == 1
    form = {
        "id": "form",
        "html_id": "form",
        "html_tag": "form",
        "capture_id": "document",
        "form_target_url": "https://example.com/save",
        "form_target_method": "POST",
    }
    planner.dom(graph.nodes[request], form, True, False, ["document"])
    assert any(edge["kind"] == "REQUESTS" for edge in planner.links.values())
    planner.dom(graph.nodes[request], form | {"form_target_url": None}, True, False, ["document"])
    planner.dom(graph.nodes[request], form | {"html_tag": "div"}, True, False, ["document"])
    assert len(planner.links) == 2



def test_candidate_selection_filters_elements_before_hydration(event):
    store = MagicMock()
    store.read.side_effect = [[{"id": "element"}], [
        {"node": {"id": "element", "kind": "element"}, "evidence_id": "proof", "contexts": []}
    ]]
    planner = LinkPlanner(store, Projection(event()))
    assert planner.candidates("capture_id", "page")[0]["evidence_id"] == "proof"
    selection = store.read.call_args_list[0].args[0]
    assert "USING INDEX other:GraphEntity(capture_id)" in selection
    assert "other.kind='element'" in selection
    assert "OPTIONAL MATCH" not in selection
    assert store.read.call_args.kwargs["ids"] == ["element"]
    with pytest.raises(ValueError, match="Unsupported"):
        planner.candidates("untrusted", "page")


def test_hydration_subdivides_memory_failures_and_preserves_results(event):
    from shyhurricane.graph.publication import PublicationConflict, PublicationMemoryError

    store = MagicMock()
    def read(statement, **parameters):
        ids = parameters["ids"]
        if len(ids) > 1:
            raise Neo4jError._hydrate_neo4j(
                code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget"
            )
        return [{"node": {"id": ids[0]}, "evidence_id": "proof", "contexts": []}]

    store.read.side_effect = read
    planner = LinkPlanner(store, Projection(event()))
    assert [row["node"]["id"] for row in planner.hydrate(["a", "b", "c"])] == ["a", "b", "c"]
    store.read.side_effect = lambda *args, **kwargs: []
    with pytest.raises(PublicationConflict, match="changed during hydration"):
        planner.hydrate(["a"])
    store.read.side_effect = Neo4jError._hydrate_neo4j(
        code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget"
    )
    with pytest.raises(PublicationMemoryError, match="hydration"):
        planner.hydrate(["a"])
    store.read.side_effect = Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
    with pytest.raises(Neo4jError):
        planner.hydrate(["a"])
