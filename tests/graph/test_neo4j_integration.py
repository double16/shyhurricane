"""Run against an isolated Neo4j with NEO4J_TEST_URI=bolt://127.0.0.1:17687."""

import json
import os
import subprocess
import threading
from pathlib import Path

import pytest
from persistqueue import Empty

from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.query import GraphQuery
from shyhurricane.graph.visibility import visible_relationship

pytestmark = pytest.mark.skipif(not os.environ.get("NEO4J_TEST_URI"), reason="Requires isolated Neo4j test instance")


@pytest.fixture
def neo4j():
    store = GraphStore(os.environ["NEO4J_TEST_URI"])
    store.ready()

    def clean():
        scope = "n.url STARTS WITH 'https://graph-test.invalid/' OR n.url STARTS WITH 'https://cdn.graph-test.invalid/'"
        with store.connect().session() as session:
            while session.run(
                f"MATCH (n) WHERE {scope} MATCH (n)-[r]-() WITH DISTINCT r LIMIT 500 DELETE r RETURN count(r) AS n"
            ).single()["n"]:
                pass
            while session.run(
                f"MATCH (n) WHERE ({scope}) AND NOT EXISTS {{ MATCH (n)--() }} "
                "WITH n LIMIT 500 DELETE n RETURN count(n) AS n"
            ).single()["n"]:
                pass

    clean()
    try:
        yield store
    finally:
        clean()
        store.close()


def runner(source, filename):
    analyzer = Path("src/docker/unix_command/graph-analysis/analyze.cjs").resolve()
    return json.loads(
        subprocess.run(
            ["node", str(analyzer)],
            input=json.dumps({"source": source, "filename": filename}),
            text=True,
            capture_output=True,
            check=True,
        ).stdout
    )


def test_latest_history_idempotency_and_reopen(neo4j, event):
    url = "https://graph-test.invalid/page"
    recent = event(url=url, body='<a href="/new">new</a>', timestamp="2026-02-01T00:00:00Z")
    old = event(url=url, body='<a href="/old">old</a>')
    neo4j.publish(extract(recent))
    neo4j.publish(extract(old))
    first = neo4j.statistics()
    neo4j.publish(extract(old))
    assert neo4j.statistics()["relationships"] == first["relationships"]
    service = GraphQuery(neo4j)
    assert not service.paths("graph-test.invalid", url, end="https://graph-test.invalid/old", mode="journey")["results"]
    assert service.paths("graph-test.invalid", url, end="https://graph-test.invalid/new", mode="journey")["results"]
    assert service.paths(
        "graph-test.invalid", url, end="https://graph-test.invalid/old", mode="journey", historical=True
    )["results"]
    neo4j.close()
    assert neo4j.ready()
    assert service.paths(
        "graph-test.invalid", url, end="https://graph-test.invalid/old", mode="journey", as_of=old["observed_at"]
    )["results"]


def test_staged_publication_preserves_previous_graph_and_replays(neo4j, event, monkeypatch):
    from shyhurricane.graph import publication

    monkeypatch.setattr(publication, "WRITE_BATCH_SIZE", 2)
    projection = extract(event(url="https://graph-test.invalid/batched", body='<a href="/a">a</a><a href="/b">b</a>'))
    original = publication.write_batches
    service = GraphQuery(neo4j)

    def fail_after_evidence(*args):
        original(*args)
        if args[2] == "evidence":
            raise RuntimeError("injected batch failure")

    monkeypatch.setattr(publication, "write_batches", fail_after_evidence)
    with pytest.raises(RuntimeError, match="injected batch failure"):
        neo4j.publish(projection)
    assert not service.elements("graph-test.invalid")["results"]
    staged_evidence = neo4j.read(
        "MATCH (e:GraphEvidence {capture_id:$id}) RETURN e.id AS id LIMIT 1", id=projection.event["id"]
    )[0]["id"]
    assert service.evidence("graph-test.invalid", staged_evidence) is None
    monkeypatch.setattr(publication, "write_batches", original)
    neo4j.publish(projection)

    def visible_relationship_count():
        return neo4j.read(f"MATCH ()-[r:RELATES]->() WHERE {visible_relationship('r')} RETURN count(r) AS n")[0]["n"]

    assert visible_relationship_count() == len(projection.edges)
    old = service.elements("graph-test.invalid")["results"]
    old_evidence = service.paths("graph-test.invalid", projection.url)["results"][0]["steps"][0]["evidence_id"]
    counts = neo4j.statistics()
    active = neo4j.read(
        "MATCH (c:GraphCapture {id:$id}) RETURN c.active_publication_id AS id", id=projection.event["id"]
    )[0]["id"]
    neo4j.publish(projection)
    assert neo4j.statistics()["relationships"] == counts["relationships"]
    assert (
        neo4j.read("MATCH (c:GraphCapture {id:$id}) RETURN c.active_publication_id AS id", id=projection.event["id"])[
            0
        ]["id"]
        == active
    )
    node = next(iter(projection.nodes.values()))
    node["name"] = "replacement name"
    monkeypatch.setattr(publication, "write_batches", fail_after_evidence)
    with pytest.raises(RuntimeError, match="injected batch failure"):
        neo4j.publish(projection)
    assert service.elements("graph-test.invalid")["results"] == old
    assert visible_relationship_count() == len(projection.edges)
    assert service.evidence("graph-test.invalid", old_evidence)
    monkeypatch.setattr(publication, "write_batches", original)
    neo4j.close()
    assert neo4j.ready()
    neo4j.publish(projection)
    replacement = service.elements("graph-test.invalid")["results"]
    assert any(item["name"] == "replacement name" for item in replacement)
    assert {item["id"] for item in old} == {item["id"] for item in replacement}
    with neo4j.connect().session() as session:
        session.run("MATCH (p:GraphPublication) WHERE p.state='retired' SET p.retired_at=0").consume()
    for _ in range(4):
        neo4j.cleanup()
    assert service.evidence("graph-test.invalid", old_evidence)
    assert not neo4j.read("MATCH (n:GraphEntity {_publication_id:$id}) RETURN n.id", id=active)


def test_reproduction_sized_capture_commits_under_restricted_transaction_memory(neo4j, event):
    from shyhurricane.graph.model import Projection

    graph = Projection(event(url="https://graph-test.invalid/large"))
    nodes = [graph.node("symbol", str(index), capture_id=graph.event["id"]) for index in range(9905)]
    for index in range(20000):
        graph.fact(
            nodes[index % len(nodes)],
            nodes[(index + 1) % len(nodes)],
            "FLOWS_TO",
            "load-test",
            location=str(index % 15140),
            snippet="x" * 1000,
        )
    assert len(graph.evidence) == 15140
    neo4j.publish(graph)
    counts = neo4j.statistics()
    assert counts["entities"] == 9905
    assert counts["relationships"] == 20000
    assert counts["captures"] == 1
    selected_nodes, relationships, metadata = GraphQuery(neo4j).snapshot("graph-test.invalid")
    assert len(selected_nodes) == 9905, metadata
    assert len(relationships) == 20000
    assert not metadata["retrieval_truncated"]
    assert (
        neo4j.read("MATCH (e:GraphEvidence {capture_id:$id}) RETURN count(e) AS n", id=graph.event["id"])[0]["n"]
        == 15140
    )


def test_legacy_capture_migrates_without_exposing_staging_or_losing_evidence(neo4j, event, monkeypatch):
    from shyhurricane.graph import publication

    graph = extract(event(url="https://graph-test.invalid/legacy", body='<a href="/next">next</a>'))
    capture = {
        "id": graph.event["id"],
        "url": graph.url,
        "host": "graph-test.invalid",
        "complete": True,
        "resource_key": "GET " + graph.url,
        "observed_at": graph.event["observed_at"],
        "gaps": [],
        "context_urls": ["https://graph-test.invalid/context"],
    }
    with neo4j.connect().session() as session:
        session.run("CREATE (c:GraphCapture) SET c += $capture", capture=capture).consume()
        session.run("UNWIND $nodes AS n CREATE (e:GraphEntity) SET e += n", nodes=list(graph.nodes.values())).consume()
        session.run(
            "UNWIND $records AS n CREATE (e:GraphEvidence) SET e += n, "
            "e.context_urls=null, e.context_owner_id=$capture",
            records=list(graph.evidence.values()),
            capture=capture["id"],
        ).consume()
        session.run(
            "UNWIND $edges AS r MATCH (a:GraphEntity {id:r.source}), (b:GraphEntity {id:r.target}) "
            "CREATE (a)-[e:RELATES]->(b) SET e += r",
            edges=list(graph.edges.values()),
        ).consume()
    service = GraphQuery(neo4j)
    original = service.elements("graph-test.invalid")["results"]
    evidence_id = next(iter(graph.evidence))
    assert service.evidence("graph-test.invalid", evidence_id)["context_urls"] == capture["context_urls"]
    original_write = publication.write_batches

    def observe_staging(*args):
        original_write(*args)
        assert service.elements("graph-test.invalid")["results"] == original

    monkeypatch.setattr(publication, "write_batches", observe_staging)
    next(iter(graph.nodes.values()))["name"] = "new legacy name"
    neo4j.publish(graph)
    assert any(item["name"] == "new legacy name" for item in service.elements("graph-test.invalid")["results"])
    assert service.evidence("graph-test.invalid", evidence_id)["context_urls"] == capture["context_urls"]


def test_crash_after_activation_replays_without_rewriting_active_generation(neo4j, event, monkeypatch):
    from neo4j.exceptions import ServiceUnavailable

    from shyhurricane.graph.publication import GraphPublisher

    graph = extract(event(url="https://graph-test.invalid/activated", body='<a href="/next">next</a>'))
    activate = GraphPublisher.activate

    def lost_acknowledgement(*args):
        activate(*args)
        raise ServiceUnavailable("connection lost after commit")

    monkeypatch.setattr(GraphPublisher, "activate", lost_acknowledgement)
    with pytest.raises(ServiceUnavailable):
        neo4j.publish(graph)
    assert GraphQuery(neo4j).elements("graph-test.invalid")["results"]
    count = neo4j.read("MATCH (p:GraphPublication) RETURN count(p) AS n")[0]["n"]
    monkeypatch.setattr(GraphPublisher, "activate", activate)
    neo4j.publish(graph)
    assert neo4j.read("MATCH (p:GraphPublication) RETURN count(p) AS n")[0]["n"] == count


def test_hydration_keeps_frozen_generation_when_reanalysis_activates_mid_read(neo4j, event, monkeypatch):
    graph = extract(event(url="https://graph-test.invalid/frozen", body='<a href="/next">next</a>'))
    neo4j.publish(graph)
    service = GraphQuery(neo4j)
    original = service.elements("graph-test.invalid")["results"]
    next(iter(graph.nodes.values()))["name"] = "changed during hydration"
    graph.gaps.append("replacement gap")
    read = neo4j.read
    activated = False

    def activate_during_read(statement, **parameters):
        nonlocal activated
        if "AS source_id" in statement and not activated:
            activated = True
            neo4j.publish(graph)
        return read(statement, **parameters)

    monkeypatch.setattr(neo4j, "read", activate_during_read)
    result = service.elements("graph-test.invalid")
    assert activated and result["results"] == original
    assert "replacement gap" not in result["analysis_gaps"]
    monkeypatch.setattr(neo4j, "read", read)
    assert "replacement gap" in service.elements("graph-test.invalid")["analysis_gaps"]


def test_external_resources_do_not_inherit_consuming_document_scope(neo4j, event):
    from shyhurricane.graph.model import Projection

    graph = Projection(event(url="https://graph-test.invalid/boundary"))
    graph.contexts = [{"id": graph.event["id"], "url": graph.url}]
    source = graph.resource(graph.url)
    external = graph.resource("https://external.invalid/")
    end = graph.resource("https://graph-test.invalid/end")
    graph.fact(source, external, "NAVIGATES_TO", "test")
    graph.fact(external, end, "NAVIGATES_TO", "test")
    neo4j.publish(graph)
    service = GraphQuery(neo4j)
    assert service.paths("graph-test.invalid", source, end=external, mode="journey")["results"]
    assert not service.paths("graph-test.invalid", source, end=end, mode="journey")["results"]


@pytest.mark.parametrize("reverse", [False, True])
def test_cross_module_flows_resolve_in_either_order(neo4j, event, reverse):
    importer = extract(
        event(
            url="https://graph-test.invalid/app.js",
            mime="text/javascript",
            body="import {send} from './send.js'; const value=location.hash; send(value);",
        ),
        javascript_runner=runner,
    )
    exporter = extract(
        event(
            url="https://graph-test.invalid/send.js",
            mime="text/javascript",
            body="export function send(input) { eval(input); }",
        ),
        javascript_runner=runner,
    )
    for projection in [exporter, importer] if reverse else [importer, exporter]:
        neo4j.publish(projection)
    source = next(node["id"] for node in importer.nodes.values() if node.get("name") == "location.hash")
    service = GraphQuery(neo4j)
    result = service.paths("graph-test.invalid", source, mode="flow", max_depth=12, detail="full")
    assert any(path["nodes"][-1].get("name") == "eval" for path in result["results"])
    module_step = next(
        step for path in result["results"] for step in path["steps"] if step.get("rule") == "js.module-link"
    )
    assert service.evidence("graph-test.invalid", module_step["evidence_id"])


def test_cdn_script_requests_resolve_against_consuming_page(neo4j, event, graph_paths, monkeypatch):
    from shyhurricane.graph.artifacts import ArtifactStore

    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    artifacts = ArtifactStore("db")
    page = event(
        url="https://graph-test.invalid/account/", body='<script src="https://cdn.graph-test.invalid/main.js"></script>'
    )
    script = event(
        url="https://cdn.graph-test.invalid/main.js",
        mime="text/javascript",
        body="import './lazy.js';const x=location.hash; fetch('submit',{method:'POST',body:x}); location.href='done';",
    )
    artifacts.register(script)
    orphan = extract(script, artifacts, javascript_runner=runner)
    assert any("consuming document" in gap for gap in orphan.gaps)
    artifacts.register(page)
    neo4j.publish(extract(page, artifacts, javascript_runner=runner))
    projection = extract(script, artifacts, javascript_runner=runner)
    neo4j.publish(projection)
    urls = {node["url"] for node in projection.nodes.values()}
    assert "https://graph-test.invalid/account/submit" in urls
    assert "https://cdn.graph-test.invalid/submit" not in urls
    service = GraphQuery(neo4j)
    journeys = service.paths(
        "https://graph-test.invalid/account/",
        page["data"]["url"],
        end="https://graph-test.invalid/account/done",
        mode="journey",
    )
    assert journeys["results"]
    assert service.evidence("graph-test.invalid", journeys["results"][0]["steps"][0]["evidence_id"])
    assert service.paths("https://graph-test.invalid/account/", script["data"]["url"], kinds=["IMPORTS"], max_depth=1)[
        "results"
    ]
    artifacts.close()


def test_dom_inputs_connect_to_delivered_script_sinks(neo4j, event, graph_paths, monkeypatch):
    from shyhurricane.graph.artifacts import ArtifactStore

    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    artifacts = ArtifactStore("db")
    page = event(
        url="https://graph-test.invalid/form", body='<input id="name" name="name"><script src="/form.js"></script>'
    )
    script = event(
        url="https://graph-test.invalid/form.js",
        mime="text/javascript",
        body="const input=document.getElementById('name').value; eval(input);",
    )
    artifacts.register(page)
    artifacts.register(script)
    html = extract(page, artifacts, javascript_runner=runner)
    neo4j.publish(html)
    neo4j.publish(extract(script, artifacts, javascript_runner=runner))
    source = next(node["id"] for node in html.nodes.values() if node.get("html_id") == "name")
    result = GraphQuery(neo4j).paths("graph-test.invalid", source, mode="flow", max_depth=12)
    assert any(path["nodes"][-1].get("name") == "eval" for path in result["results"])
    artifacts.close()


def test_shared_script_reanalysis_coalesces_and_keeps_all_page_relationships(neo4j, event, graph_paths, monkeypatch):
    from shyhurricane.graph import worker
    from shyhurricane.graph.artifacts import ArtifactStore
    from shyhurricane.persistent_queue import get_persistent_queue

    script = event(
        url="https://cdn.graph-test.invalid/shared.js",
        mime="text/javascript",
        body="const input=location.hash;fetch('submit',{method:'POST',body:input});",
    )
    pages = [
        event(
            url=f"https://graph-test.invalid/shared/{index}/",
            body='<script src="https://cdn.graph-test.invalid/shared.js"></script>',
        )
        for index in range(10)
    ]
    artifacts = ArtifactStore("db")
    for capture in [script, *pages]:
        artifacts.register(capture)
    artifacts.close()
    queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    for page in pages:
        queue.put(page)
    queue.close()
    publications = []
    publish = neo4j.publish

    def record(projection):
        publications.append(projection.event["id"])
        publish(projection)

    def available(queue, **kwargs):
        while True:
            try:
                yield queue.get(block=False)
            except Empty:
                return

    monkeypatch.setattr(neo4j, "publish", record)
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "GraphStore", lambda *args: neo4j)
    monkeypatch.setattr(worker, "persistent_queue_get", available)
    monkeypatch.setattr(worker, "extract", lambda *args, **kwargs: extract(*args, **kwargs, javascript_runner=runner))
    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    health = threading.Event()
    health.set()
    worker.graph_worker("db", neo4j.location, health, threading.Event(), False)
    assert publications.count(script["id"]) == 1
    assert len(publications) == len(pages) + 1
    rows = neo4j.read(
        "MATCH ()-[r:RELATES]->(target:GraphEntity) WHERE r.capture_id=$id AND r.kind='REQUESTS' "
        "RETURN DISTINCT target.url AS url",
        id=script["id"],
    )
    assert {row["url"] for row in rows} == {page["data"]["url"] + "submit" for page in pages}
    reopened = get_persistent_queue("db", "graph_queue", auto_resume=False)
    try:
        assert reopened.unack_count() == reopened.ready_count() == 0
    finally:
        reopened.close()


@pytest.mark.skipif(not os.environ.get("GRAPH_ANALYZER_TEST_IMAGE"), reason="Requires built analyzer image")
def test_production_container_parses_without_executing(monkeypatch):
    from shyhurricane.graph import extract as extractor

    monkeypatch.setattr(extractor, "unix_command_image", lambda: os.environ["GRAPH_ANALYZER_TEST_IMAGE"])
    result = extractor.run_javascript("while(true){};const input=location.hash;eval(input);", "app.js")
    assert any(node["role"] == "sink" for node in result["nodes"])


def test_stock_check_published_response_flow_and_form_request(neo4j, event, graph_paths, monkeypatch):
    from shyhurricane.graph.artifacts import ArtifactStore

    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    source = Path("src/docker/unix_command/graph-analysis/test/stockCheck.js").read_text()
    page = event(
        url="https://graph-test.invalid/product",
        body="""<form id="stockCheckForm" method="POST"
      action="/stock"><input name="productId"><select name="storeId"></select></form>
      <script src="/stockCheck.js"></script>""",
    )
    script = event(url="https://graph-test.invalid/stockCheck.js", body=source, mime="text/javascript")
    artifacts = ArtifactStore("db")
    try:
        artifacts.register(page)
        neo4j.publish(extract(page, artifacts, javascript_runner=runner))
        projection = extract(script, artifacts, javascript_runner=runner)
        neo4j.publish(projection)
        sink = next(
            node for node in projection.nodes.values() if node["kind"] == "sink" and node["name"] == ".innerHTML"
        )
        query = GraphQuery(neo4j)
        result = query.paths(script["data"]["url"], sink["id"], direction="backward", mode="flow", max_depth=8)
        assert any(path["nodes"][-1]["name"] == "res.text" for path in result["results"])
        for path in result["results"]:
            for step in path["steps"]:
                assert query.evidence("graph-test.invalid", step["evidence_id"])["snippet"]
        request = next(node for node in projection.nodes.values() if node.get("form_request"))
        _, edges, _ = query.snapshot("graph-test.invalid")
        assert any(edge["source"] == request["id"] and edge["kind"] == "REQUESTS" for edge in edges)
        controls = query.elements("graph-test.invalid", kinds=["element"], detail="full")["results"]
        for control in (node for node in controls if node.get("field_name")):
            assert query.paths("graph-test.invalid", control["id"], end=request["id"], mode="flow")["results"]
            assert not query.paths("graph-test.invalid", control["id"], end=sink["id"], mode="flow")["results"]
    finally:
        artifacts.close()


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0), (1, 0, 2)])
def test_reexport_async_returns_publish_in_either_order_and_respect_versions(neo4j, event, order):
    sources = [
        ("app.js", "import {pass} from './barrel.js'; async function run(){eval(await pass(location.hash));}"),
        ("barrel.js", "export {identity as pass} from './api.js';"),
        ("api.js", "export async function identity(value){return value;}"),
    ]
    projections = [
        extract(
            event(url=f"https://graph-test.invalid/{name}", mime="text/javascript", body=body), javascript_runner=runner
        )
        for name, body in sources
    ]
    for index in order:
        neo4j.publish(projections[index])
    source = next(node for node in projections[0].nodes.values() if node["name"] == "location.hash")
    query = GraphQuery(neo4j)
    result = query.paths("graph-test.invalid", source["id"], mode="flow", max_depth=32, detail="full")
    assert any(path["nodes"][-1]["name"] == "eval" for path in result["results"])
    for path in result["results"]:
        for step in path["steps"]:
            assert query.evidence("graph-test.invalid", step["evidence_id"])["snippet"]
    # Replacing the barrel must invalidate shortcuts owned by other captures too.
    changed = event(
        url="https://graph-test.invalid/barrel.js",
        mime="text/javascript",
        body="export function pass(value){return 'safe';}",
        timestamp="2026-02-01T00:00:00Z",
    )
    neo4j.publish(extract(changed, javascript_runner=runner))
    assert not query.paths("graph-test.invalid", source["id"], mode="flow", max_depth=32)["results"]
    assert query.paths("graph-test.invalid", source["id"], mode="flow", max_depth=32, historical=True)["results"]
