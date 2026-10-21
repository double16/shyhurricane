"""Run against an isolated Neo4j with NEO4J_TEST_URI=bolt://127.0.0.1:17687."""

import json
import os
import subprocess
import threading
import time
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
        with store.connect().session(database="neo4j") as session:
            session.run("MATCH (m:GraphState {id:'graph_lookup_v1'}) DELETE m").consume()
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


def test_pending_cleanup_uses_index_and_excludes_cleaned_history(neo4j):
    url = "https://graph-test.invalid/cleanup"
    with neo4j.connect().session(database="neo4j") as session:
        session.run(
            "UNWIND range(0,4999) AS i CREATE (p:GraphPublication "
            "{id:'cleanup-history-'+toString(i),url:$url,state:'retired',retired_at:0,cleaned:true})",
            url=url,
        ).consume()
        session.run(
            "CREATE (c:GraphCapture {id:'cleanup-owner',url:$url}), "
            "(p:GraphPublication:GraphCleanupPending {id:'cleanup-pending',capture_id:'cleanup-owner',url:$url,"
            "state:'abandoned',retired_at:0}), "
            "(e:GraphEvidence {id:'cleanup-abandoned-proof',_publication_id:'cleanup-pending',url:$url}), "
            "(active:GraphPublication:GraphCleanupPending "
            "{id:'cleanup-active',capture_id:'cleanup-owner',url:$url,state:'published',retired_at:0}), "
            "(staging:GraphPublication:GraphCleanupPending "
            "{id:'cleanup-staging',capture_id:'cleanup-owner',url:$url,state:'staging',retired_at:0}) "
            "SET c.active_publication_id=active.id,c.staging_publication_id=staging.id",
            url=url,
        ).consume()

    with neo4j.connect().session(database="neo4j", default_access_mode="READ") as session:
        with session.begin_transaction(timeout=10) as tx:
            result = tx.run(
                "PROFILE MATCH (p:GraphPublication:GraphCleanupPending) "
                "USING INDEX p:GraphCleanupPending(retired_at,id) "
                "WHERE p.retired_at<1 AND p.id IS NOT NULL "
                "AND p.state IN ['retired','abandoned'] AND coalesce(p.cleaned,false)=false "
                "RETURN p.id AS id ORDER BY p.retired_at,p.id LIMIT 5"
            )
            assert [row["id"] for row in result] == ["cleanup-pending"]
            profile = result.consume().profile

    def operators(plan):
        yield plan
        for child in plan.get("children", []):
            yield from operators(child)

    seeks = [plan for plan in operators(profile) if "NodeIndexSeek" in plan["operatorType"]]
    assert seeks and sum(plan["rows"] for plan in seeks) <= 3
    assert neo4j.cleanup() == {"selected": 1, "completed": 1, "deleted": 1}
    assert neo4j.cleanup() == {"selected": 0, "completed": 0, "deleted": 0}
    assert not neo4j.read("MATCH (e:GraphEvidence {id:'cleanup-abandoned-proof'}) RETURN e.id")
    assert len(neo4j.read(
        "MATCH (p:GraphPublication) WHERE p.id IN ['cleanup-active','cleanup-staging'] RETURN p.id"
    )) == 2


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
    assert service.evidence(staged_evidence) is None
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
    assert service.evidence(old_evidence)
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
    assert service.evidence(old_evidence)
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
    assert service.evidence(evidence_id)["context_urls"] == capture["context_urls"]
    original_write = publication.write_batches

    def observe_staging(*args):
        original_write(*args)
        assert service.elements("graph-test.invalid")["results"] == original

    monkeypatch.setattr(publication, "write_batches", observe_staging)
    next(iter(graph.nodes.values()))["name"] = "new legacy name"
    neo4j.publish(graph)
    assert any(item["name"] == "new legacy name" for item in service.elements("graph-test.invalid")["results"])
    assert service.evidence(evidence_id)["context_urls"] == capture["context_urls"]


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
    assert service.evidence(module_step["evidence_id"])


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
    assert service.evidence(journeys["results"][0]["steps"][0]["evidence_id"])
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


def test_published_form_response_flow_and_request(neo4j, event, graph_paths, monkeypatch):
    from shyhurricane.graph.artifacts import ArtifactStore

    monkeypatch.setattr("shyhurricane.index.web_resources_pipeline._deobfuscate_javascript", lambda source: source)
    source = Path("src/docker/unix_command/graph-analysis/test/dataFlow.js").read_text()
    page = event(
        url="https://graph-test.invalid/form",
        body="""<form id="dataForm" method="POST"
      action="/submit"><input name="fieldOne"><select name="fieldTwo"></select></form>
      <script src="/dataFlow.js"></script>""",
    )
    script = event(url="https://graph-test.invalid/dataFlow.js", body=source, mime="text/javascript")
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
                assert query.evidence(step["evidence_id"])["snippet"]
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
            assert query.evidence(step["evidence_id"])["snippet"]
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


@pytest.mark.parametrize("storage", ["inline", "publication", "capture", "archive"])
def test_element_filters_preserve_effective_contexts_and_require_same_endpoint(neo4j, storage):
    from shyhurricane.graph.model import identity

    page = "https://graph-test.invalid/filter-page"
    other = "https://graph-test.invalid/other-page"
    script = "https://cdn.graph-test.invalid/filters.js"
    owner = "filter-context-owner"
    capture = "filter-capture"
    nodes = [
        {
            "id": "context-source",
            "url": script,
            "kind": "result",
            "role": "source",
            "name": "context source",
            "capture_id": capture,
            "context_urls": [page],
        },
        {
            "id": "direct-sink",
            "url": page,
            "kind": "call",
            "role": "sink",
            "name": "direct sink",
            "capture_id": capture,
        },
        {
            "id": "wrong-source",
            "url": script,
            "kind": "result",
            "role": "source",
            "name": "wrong context",
            "capture_id": capture,
            "context_urls": [other],
        },
    ]
    if storage != "inline":
        nodes[0].update(context_owner_id=owner, context_urls=[other])
    with neo4j.connect().session() as session:
        session.run(
            "CREATE (:GraphCapture {id:$capture,url:$script,host:'cdn.graph-test.invalid',complete:true, "
            "resource_key:$script,observed_at:1.0})",
            capture=capture,
            script=script,
        ).consume()
        session.run("UNWIND $nodes AS row CREATE (n:GraphEntity) SET n += row", nodes=nodes).consume()
        session.run(
            "MATCH (a:GraphEntity {id:'context-source'}), (b:GraphEntity {id:'direct-sink'}), "
            "(wrong:GraphEntity {id:'wrong-source'}) "
            "CREATE (a)-[:RELATES {id:'matching-edge',capture_id:$capture}]->(b), "
            "(wrong)-[:RELATES {id:'split-predicate-edge',capture_id:$capture}]->(b)",
            capture=capture,
        ).consume()
        if storage in {"capture", "archive"}:
            session.run(
                "CREATE (:GraphCapture {id:$owner,url:$script,host:'cdn.graph-test.invalid', context_urls:$contexts})",
                owner=owner,
                script=script,
                contexts=[page] if storage == "capture" else [other],
            ).consume()
        if storage in {"publication", "archive"}:
            session.run(
                "CREATE (:GraphPublication {id:$id,capture_id:$owner,url:$script,context_urls:[$page]})",
                id=owner if storage == "publication" else identity("legacy-publication", owner),
                owner=owner,
                script=script,
                page=page,
            ).consume()
    service = GraphQuery(neo4j)
    baseline = service.elements("graph-test.invalid", detail="full")["results"]
    for role in (None, "source", "sink"):
        for context in (None, page, other):
            expected = [
                node
                for node in baseline
                if (role is None or node.get("role") == role)
                and (context is None or node["url"] == context or context in node.get("context_urls", []))
            ]
            result = service.elements("graph-test.invalid", role=role, context_url=context, detail="full")
            assert result["results"] == expected
    result = service.elements("graph-test.invalid", role="source", context_url=page)
    assert [node["id"] for node in result["results"]] == ["context-source"]
    # Checking membership, rather than just final Python filtering, catches split-endpoint matches.
    memberships = []
    read = neo4j.read

    def record(statement, **parameters):
        rows = read(statement, **parameters)
        if "AS membership_id" in statement:
            memberships.extend(row["membership_id"] for row in rows)
        return rows

    neo4j.read = record
    service.elements("graph-test.invalid", role="source", context_url=page)
    assert memberships == ["matching-edge"]
    assert [node["id"] for node in service.elements(page, role="source", context_url=page)["results"]] == [
        "context-source"
    ]
    if storage != "inline":
        # An explicit empty normalized context suppresses stale inline/capture context values.
        label = "GraphCapture" if storage == "capture" else "GraphPublication"
        context_id = identity("legacy-publication", owner) if storage == "archive" else owner
        with neo4j.connect().session() as session:
            session.run(f"MATCH (n:{label} {{id:$id}}) SET n.context_urls=[]", id=context_id).consume()
        assert not service.elements("graph-test.invalid", role="source", context_url=page)["results"]


def test_focused_elements_are_not_displaced_by_unrelated_relationship_limit(neo4j):
    with neo4j.connect().session() as session:
        session.run(
            "CREATE (:GraphCapture {id:'filter-budget',url:'https://graph-test.invalid/budget', "
            "host:'graph-test.invalid',resource_key:'filter-budget',complete:true,observed_at:1.0}), "
            "(a:GraphEntity {id:'budget-a',kind:'result',url:'https://graph-test.invalid/budget',name:'noise'}), "
            "(b:GraphEntity {id:'budget-b',kind:'result',url:'https://graph-test.invalid/budget',name:'target', "
            "role:'source'}), "
            "(c:GraphEntity {id:'budget-c',kind:'result',url:'https://graph-test.invalid/budget',name:'noise'}) "
            "WITH a,b,c UNWIND range(1,20001) AS i "
            "CREATE (a)-[:RELATES {id:'a'+toString(i),capture_id:'filter-budget'}]->(c) "
            "WITH DISTINCT b,c CREATE (b)-[:RELATES {id:'z-focused',capture_id:'filter-budget'}]->(c)"
        ).consume()
    service = GraphQuery(neo4j)
    result = service.elements("graph-test.invalid", role="source", context_url="https://graph-test.invalid/budget")
    assert [node["id"] for node in result["results"]] == ["budget-b"]
    assert not result["retrieval_truncated"]


def test_filtered_elements_keep_temporal_and_staged_publication_visibility(neo4j, event, monkeypatch):
    from shyhurricane.graph import publication
    from shyhurricane.graph.model import Projection

    url = "https://graph-test.invalid/filter-versions"

    def projection(timestamp, role):
        graph = Projection(event(url=url, timestamp=timestamp))
        resource = graph.resource(url)
        node = graph.node("result", f"candidate-{role}", role=role, capture_id=graph.event["id"])
        graph.fact(resource, node, "CONTAINS", "test-filter")
        return graph

    old = projection("2026-01-01T00:00:00Z", "source")
    recent = projection("2026-02-01T00:00:00Z", "sink")
    neo4j.publish(old)
    neo4j.publish(recent)
    service = GraphQuery(neo4j)
    for options in ({}, {"historical": True}, {"as_of": old.event["observed_at"]}):
        baseline = service.elements("graph-test.invalid", detail="full", **options)["results"]
        for role in ("source", "sink"):
            result = service.elements("graph-test.invalid", role=role, context_url=url, detail="full", **options)
            assert result["results"] == [node for node in baseline if node.get("role") == role]
    before = service.elements("graph-test.invalid", role="sink", context_url=url)
    original_write = publication.write_batches

    def check_staged(*args):
        original_write(*args)
        assert service.elements("graph-test.invalid", role="sink", context_url=url) == before

    monkeypatch.setattr(publication, "write_batches", check_staged)
    next(node for node in recent.nodes.values() if node.get("role") == "sink")["name"] = "replacement"
    neo4j.publish(recent)
    assert service.elements("graph-test.invalid", role="sink", context_url=url)["results"][0]["name"] == "replacement"


def test_hydration_queries_seek_existing_id_indexes(neo4j, event, monkeypatch):
    graph = extract(event(url="https://graph-test.invalid/hydration-plan", body='<a href="/next">next</a>'))
    neo4j.publish(graph)
    read = neo4j.read
    plans = {}

    def operators(plan):
        return [plan["operatorType"]] + [
            operator for child in plan.get("children", []) for operator in operators(child)
        ]

    def inspect(statement, **parameters):
        if "USING INDEX SEEK" in statement:
            with neo4j.connect().session(database="neo4j") as session:
                summary = session.run("EXPLAIN " + statement, **parameters).consume()
                plans["relationships" if "AS source_id" in statement else "entities"] = operators(summary.plan)
        return read(statement, **parameters)

    monkeypatch.setattr(neo4j, "read", inspect)
    assert GraphQuery(neo4j).elements("graph-test.invalid")["results"]
    assert any("DirectedRelationshipIndexSeek" in operator for operator in plans["relationships"])
    assert any("NodeUniqueIndexSeek" in operator for operator in plans["entities"])
    assert all("Unwind" not in operator and "Apply" not in operator for plan in plans.values() for operator in plan)


def frontier_projection(event, *, timestamp="2026-01-01T00:00:00Z"):
    from shyhurricane.graph.model import Projection

    graph = Projection(event(url="https://graph-test.invalid/frontier", timestamp=timestamp))
    source = graph.node("source", "frontier-source", role="source", capture_id=graph.event["id"])
    middle = graph.node("symbol", "frontier-middle", capture_id=graph.event["id"])
    sink = graph.node("sink", "frontier-sink", role="sink", capture_id=graph.event["id"])
    graph.fact(source, middle, "FLOWS_TO", "test.frontier")
    graph.fact(middle, sink, "CALL_ARGUMENT", "test.frontier")
    return graph, source, middle, sink


def test_frontier_ignores_disconnected_relationships_and_uses_indexed_anchors(neo4j, event, monkeypatch):
    import time

    graph, source, _, sink = frontier_projection(event)
    neo4j.publish(graph)
    with neo4j.connect().session() as session:
        session.run(
            "CREATE (:GraphCapture {id:'frontier-noise',url:'https://graph-test.invalid/noise', "
            "host:'graph-test.invalid',resource_key:'frontier-noise',complete:true,observed_at:1.0}), "
            "(a:GraphEntity {id:'frontier-noise-a',kind:'symbol',url:'https://graph-test.invalid/noise'}), "
            "(b:GraphEntity {id:'frontier-noise-b',kind:'symbol',url:'https://graph-test.invalid/noise'}) "
            "WITH a,b UNWIND range(1,22001) AS i "
            "CREATE (a)-[:RELATES {id:'!'+toString(i),kind:'FLOWS_TO',capture_id:'frontier-noise'}]->(b)"
        ).consume()
    read = neo4j.read
    hydrated = set()
    profiles = {}

    def inspect(statement, **parameters):
        if "AS source_id" in statement:
            hydrated.update(parameters["ids"])
            assert len(parameters["ids"]) <= 500
        if "traversal:frontier" in statement and "frontier" not in profiles:
            with neo4j.connect().session() as session:
                rows = session.run("PROFILE " + statement, **parameters)
                list(rows)
                profiles["frontier"] = rows.consume().profile
        if "traversal:seeds" in statement and "seeds" not in profiles:
            with neo4j.connect().session() as session:
                profiles["seeds"] = session.run("EXPLAIN " + statement, **parameters).consume().plan
        return read(statement, **parameters)

    monkeypatch.setattr(neo4j, "read", inspect)
    service = GraphQuery(neo4j)
    monkeypatch.setattr(service, "snapshot", lambda *a, **kw: pytest.fail("No whole-scope snapshot"))
    for trial in range(3):
        started = time.monotonic()
        result = service.paths("graph-test.invalid", source, end=sink, mode="flow")
        print(f"frontier trial={trial + 1} seconds={time.monotonic() - started:.3f} hydrated={len(hydrated)}")
        assert result["results"] and not result["retrieval_truncated"]
    assert len(hydrated) == 2

    def walk(plan):
        return [plan] + [node for child in plan.get("children", []) for node in walk(child)]

    assert any(
        "IndexSeek" in node["operatorType"] and "anchor" in node["args"].get("Details", "")
        for node in walk(profiles["frontier"])
    )
    assert not any("AllNodesScan" in node["operatorType"] for node in walk(profiles["seeds"]))
    print(f"frontier profile DB hits={sum(node.get('dbHits', 0) for node in walk(profiles['frontier']))}")


@pytest.mark.parametrize("new_capture", [False, True])
def test_frontier_revision_survives_reanalysis_and_new_observations(neo4j, event, monkeypatch, new_capture):
    graph, source, _, sink = frontier_projection(event)
    neo4j.publish(graph)
    revised, _, _, _ = frontier_projection(
        event, timestamp="2026-02-01T00:00:00Z" if new_capture else "2026-01-01T00:00:00Z"
    )
    revised.nodes[sink]["name"] = "replacement"
    revised.edges = {key: edge for key, edge in revised.edges.items() if edge["kind"] != "CALL_ARGUMENT"}
    read = neo4j.read
    replaced = False

    def replace_between_frontiers(statement, **parameters):
        nonlocal replaced
        if "traversal:frontier" in statement and not replaced:
            replaced = True
            neo4j.publish(revised)
        return read(statement, **parameters)

    monkeypatch.setattr(neo4j, "read", replace_between_frontiers)
    service = GraphQuery(neo4j)
    original = service.paths("graph-test.invalid", source, end=sink, mode="flow")
    assert replaced and original["results"]
    assert original["results"][0]["nodes"][-1]["name"] != "replacement"
    assert not service.paths("graph-test.invalid", source, end=sink, mode="flow")["results"]
    if new_capture:
        assert service.paths("graph-test.invalid", source, end=sink, mode="flow", as_of=graph.event["observed_at"])[
            "results"
        ]
        assert service.paths("graph-test.invalid", source, end=sink, mode="flow", historical=True)["results"]


def test_frontier_revision_zero_compatibility_excludes_previously_retired_generations(neo4j, event):
    graph, source, _, sink = frontier_projection(event)
    neo4j.publish(graph)
    graph.edges = {key: edge for key, edge in graph.edges.items() if edge["kind"] != "CALL_ARGUMENT"}
    neo4j.publish(graph)
    with neo4j.connect().session() as session:
        session.run("MATCH (p:GraphPublication) REMOVE p.published_revision,p.retired_revision").consume()
    assert not GraphQuery(neo4j).paths("graph-test.invalid", source, end=sink, mode="flow")["results"]


def test_legacy_frontier_is_frozen_while_first_generation_is_published(neo4j, event, monkeypatch):
    graph, source, _, sink = frontier_projection(event)
    capture = {
        "id": graph.event["id"],
        "url": graph.url,
        "host": "graph-test.invalid",
        "complete": True,
        "resource_key": "GET " + graph.url,
        "observed_at": graph.event["observed_at"],
        "gaps": [],
    }
    with neo4j.connect().session() as session:
        session.run("CREATE (c:GraphCapture) SET c += $capture", capture=capture).consume()
        session.run(
            "UNWIND $nodes AS row CREATE (n:GraphEntity) SET n += row", nodes=list(graph.nodes.values())
        ).consume()
        session.run(
            "UNWIND $edges AS row MATCH (a:GraphEntity {id:row.source}), (b:GraphEntity {id:row.target}) "
            "CREATE (a)-[r:RELATES]->(b) SET r += row",
            edges=list(graph.edges.values()),
        ).consume()
    revised, _, _, _ = frontier_projection(event)
    revised.edges = {key: edge for key, edge in revised.edges.items() if edge["kind"] != "CALL_ARGUMENT"}
    read = neo4j.read
    activated = False

    def activate_between_reads(statement, **parameters):
        nonlocal activated
        if "traversal:frontier" in statement and not activated:
            activated = True
            neo4j.publish(revised)
        return read(statement, **parameters)

    monkeypatch.setattr(neo4j, "read", activate_between_reads)
    service = GraphQuery(neo4j)
    assert service.paths("graph-test.invalid", source, end=sink, mode="flow")["results"]
    assert activated
    assert not service.paths("graph-test.invalid", source, end=sink, mode="flow")["results"]



def test_link_planning_selects_indexed_candidates_before_hydration(neo4j, event, monkeypatch):
    from shyhurricane.graph import links
    from shyhurricane.graph.links import LinkPlanner
    from shyhurricane.graph.model import Projection

    url = "https://graph-test.invalid/link-planning"
    projection = Projection(event(url=url))
    capture = projection.event["id"]
    with neo4j.connect().session() as session:
        session.run(
            "UNWIND $owners AS owner CREATE (c:GraphCapture) SET c=owner",
            owners=[
                {"id": "lp-legacy", "url": url, "complete": True, "context_capture_ids": [capture]},
                {"id": "lp-active", "url": url, "complete": True, "active_publication_id": "lp-generation"},
            ],
        ).consume()
        session.run(
            "UNWIND range(1,6000) AS i CREATE (:GraphEntity {id:'lp-noise-'+toString(i),"
            "url:$url, capture_id:'lp-legacy', kind:'symbol', module_key:'unrelated'})",
            url=url,
        ).consume()
        session.run(
            "UNWIND $nodes AS node CREATE (n:GraphEntity) SET n=node",
            nodes=[
                {"id": "lp-a", "url": url, "capture_id": "lp-legacy", "kind": "element", "html_id": "name"},
                {"id": "lp-b", "url": url, "capture_id": "lp-active", "kind": "element",
                 "_publication_id": "lp-generation", "_owner_capture_id": "lp-active", "html_id": "name"},
                {"id": "lp-retired", "url": url, "capture_id": "lp-active", "kind": "element",
                 "_publication_id": "lp-retired-generation", "_owner_capture_id": "lp-active"},
                {"id": "lp-staged", "url": url, "capture_id": "lp-active", "kind": "element",
                 "_publication_id": "lp-staged-generation", "_owner_capture_id": "lp-active"},
                {"id": "lp-import", "url": url, "capture_id": "lp-legacy", "kind": "symbol",
                 "import_key": "lp-module", "imported_name": "read", "parameter_index": 0, "selector": "#name"},
                {"id": "lp-export", "url": url, "capture_id": "lp-legacy", "kind": "symbol",
                 "module_key": "lp-module", "export_names": ["read"], "parameter_index": 0},
                {"id": "lp-own", "url": url, "capture_id": capture, "kind": "element"},
            ],
        ).consume()
        session.run(
            "MATCH (a:GraphEntity {id:'lp-import'}), (b:GraphEntity {id:'lp-a'}) "
            "CREATE (a)-[:RELATES {id:'lp-proof-z',capture_id:'lp-legacy',evidence_id:'z'}]->(b), "
            "(a)-[:RELATES {id:'lp-proof-a',capture_id:'lp-legacy',evidence_id:'a'}]->(b)",
        ).consume()
    monkeypatch.setattr(links, "READ_BATCH_SIZE", 1)
    original = neo4j.read
    plans = []
    def observed(statement, **parameters):
        if "RETURN other.id AS id" in statement:
            with neo4j.connect().session() as session:
                summary = session.run("EXPLAIN " + statement, **parameters).consume()
                def operators(plan):
                    return [plan["operatorType"], *[
                        name for child in plan.get("children", []) for name in operators(child)
                    ]]
                plans.append(operators(summary.plan))
        return original(statement, **parameters)
    monkeypatch.setattr(neo4j, "read", observed)
    planner = LinkPlanner(neo4j, projection)
    legacy = planner.candidates("capture_id", "lp-legacy")
    assert [row["node"]["id"] for row in legacy] == ["lp-a"]
    assert legacy[0]["evidence_id"] == "a"
    assert legacy[0]["contexts"] == [capture]
    assert [row["node"]["id"] for row in planner.candidates("capture_id", "lp-active")] == ["lp-b"]
    assert planner.candidates("capture_id", capture) == []
    assert planner.candidates("capture_id", "missing") == []
    assert planner.candidates("module_key", "lp-module")[0]["node"]["id"] == "lp-export"
    assert planner.candidates("import_key", "lp-module")[0]["node"]["id"] == "lp-import"
    assert planner.candidates("selector", "#name")[0]["node"]["id"] == "lp-import"
    assert all(not any("NodeByLabelScan" in operator for operator in plan) for plan in plans), plans
    assert any(any("NodeIndexSeek" in operator for operator in plan) for plan in plans), plans


def test_resumable_planning_covers_12538_contexts_before_atomic_activation(neo4j, event):
    import time

    from shyhurricane.graph.links import LinkPlanner
    from shyhurricane.graph.model import Projection, projection_snapshot, restore_projection

    count = 12538
    projection = Projection(event(url="https://graph-test.invalid/resumable.js", body="script", mime="text/javascript"))
    projection.library_analysis = "summary"
    projection.contexts = [{"id": f"resume-page-{index:05}", "url": f"https://graph-test.invalid/resume/{index}"}
                           for index in range(count)]
    resource = projection.resource(projection.url)
    selector = projection.node("symbol", "query", capture_id=projection.event["id"], selector="#match")
    projection.fact(resource, selector, "CONTAINS", "test")
    with neo4j.connect().session() as session:
        for offset in range(0, count, 500):
            rows = [{"id": f"resume-page-{index:05}", "url": f"https://graph-test.invalid/resume/{index}"}
                    for index in range(offset, min(offset + 500, count))]
            session.run(
                "UNWIND $rows AS row CREATE (:GraphCapture {id:row.id,url:row.url,complete:true}) "
                "CREATE (:GraphEntity {id:row.id+'-element',capture_id:row.id,url:row.url,"
                "kind:'element',html_id:'match'}) "
                "CREATE (:GraphEntity {id:row.id+'-noise',capture_id:row.id,url:row.url,kind:'symbol'})", rows=rows,
            ).consume()
    revision = neo4j.activity()["publication_revision"]
    planner = LinkPlanner(neo4j, projection)
    started = time.perf_counter()
    slices, maximum = 0, 0
    while True:
        before = time.perf_counter()
        complete = planner.plan_slice()
        maximum = max(maximum, time.perf_counter() - before)
        slices += 1
        if slices == 10:
            assert neo4j.activity()["publication_revision"] == revision
            state = json.loads(json.dumps(planner.checkpoint()))
            projection = restore_projection(json.loads(json.dumps(projection_snapshot(projection))))
            planner = LinkPlanner(neo4j, projection)
            planner.restore(state)
        if complete:
            break
    elapsed = time.perf_counter() - started
    assert slices == 126 and planner.cursor["context"] == count
    assert planner.selection_reads == planner.hydration_reads == 126
    assert len(planner.links) == count and maximum <= 35 and elapsed < 30
    projection.planned_links = planner.links
    neo4j.publish(projection)
    assert neo4j.activity()["publication_revision"] == revision + 1
    assert neo4j.read("MATCH (c:GraphCapture {id:$id}) RETURN c.entity_estimate AS entities, "
                      "c.relationship_estimate AS relationships", id=projection.event["id"])[0] == {
        "entities": len(projection.nodes), "relationships": len(projection.edges) + count,
    }
    print(json.dumps({"contexts": count, "slices": slices, "selection_reads": planner.selection_reads,
                      "hydration_reads": planner.hydration_reads, "planning_seconds": round(elapsed, 3),
                      "max_slice_seconds": round(maximum, 3)}))


def test_indexed_discovery_matches_legacy_and_avoids_global_scans(neo4j, event):
    from shyhurricane.graph.lookup import migrate_lookup

    url = "https://graph-test.invalid/indexed"
    graph = extract(event(url=url, body='<form action="/save"><input name="value"></form><script src="/app.js"></script>'))
    neo4j.publish(graph)
    legacy = GraphQuery(neo4j)
    expected_elements = legacy.elements("graph-test.invalid")["results"]
    expected_endpoints = legacy.endpoints("graph-test.invalid")["results"]
    migrate_lookup(neo4j, time.monotonic() + 60, threading.Event())
    statements = []
    original = neo4j.read

    def record(statement, **parameters):
        statements.append((statement, dict(parameters)))
        return original(statement, **parameters)

    neo4j.read = record
    try:
        actual = GraphQuery(neo4j)
        assert actual.elements("graph-test.invalid")["results"] == expected_elements
        assert actual.endpoints("graph-test.invalid")["results"] == expected_endpoints
        assert actual.elements("graph-test.invalid", kinds=["field"], url=url)["results"]
        assert not actual.elements("badgraph-test.invalid")["results"]
        assert not actual.elements("graph-test.invalid:8443")["results"]
        assert actual.elements(url, context_url=url)["results"]
        assert not actual.endpoints("graph-test.invalid", method="POST")["results"]
    finally:
        neo4j.read = original
    with neo4j.connect().session() as session:
        for statement, parameters in statements:
            if "traversal:candidates" not in statement and "indexed-context" not in statement:
                continue
            parameters.pop("timeout", None)
            summary = session.run("EXPLAIN " + statement, **parameters).consume()
            plan = str(summary.plan)
            assert "NodeByLabelScan" not in plan and "AllNodesScan" not in plan
            assert "Index" in plan


def test_indexed_context_resolves_resource_flow_without_scanning(neo4j, event):
    import time

    from shyhurricane.graph.lookup import migrate_lookup
    from shyhurricane.graph.model import Projection

    page = "https://graph-test.invalid/context-page"
    script = "https://cdn.graph-test.invalid/context.js"
    graph = Projection(event(url=script, mime="text/javascript"))
    graph.contexts = [{"id": graph.event["id"], "url": page}]
    resource = graph.resource(script)
    source = graph.node("source", "location", role="source", context_urls=[page])
    sink = graph.node("sink", "eval", role="sink", context_urls=[page])
    graph.fact(resource, source, "CONTAINS", "test")
    graph.fact(resource, sink, "CONTAINS", "test")
    graph.fact(source, sink, "FLOWS_TO", "test")
    neo4j.publish(graph)
    migrate_lookup(neo4j, time.monotonic() + 60, threading.Event())
    actual = GraphQuery(neo4j)
    assert actual.elements(page, role="source", context_url=page)["results"][0]["id"] == source
    result = actual.paths("graph-test.invalid", resource, mode="flow")
    assert result["results"] and not result["retrieval_truncated"]
    assert all(step["kind"] == "FLOWS_TO" for path in result["results"] for step in path["steps"])


@pytest.mark.parametrize("label,field", [("GraphEntity", "url"), ("GraphContext", "url"),
                                         ("GraphEntity", "_reverse_host"), ("GraphContext", "reverse_host")])
def test_candidate_keyset_pages_cover_repeated_values_with_reverse_ids(neo4j, label, field):
    from shyhurricane.graph.lookup import reverse_host
    from shyhurricane.graph.traversal import TraversalSnapshot

    url = "https://graph-test.invalid/keyset/"
    prefix = url if field == "url" else reverse_host(url)
    records = [
        {"id": f"keyset-{1200 - index:04}", "url": f"{url}{index // 3:04}",
         field: f"{prefix}{index // 3:04}"}
        for index in range(1200)
    ]
    with neo4j.connect().session(database="neo4j") as session:
        session.run(f"UNWIND $rows AS row CREATE (n:{label}) SET n=row", rows=records).consume()
    reader = TraversalSnapshot(GraphQuery(neo4j), "graph-test.invalid")
    pages = []
    for page in reader.lookup_pages(label, field, prefix):
        pages.append(page)
        assert len(pages) <= 3, "Candidate pagination revisited an earlier page"
    expected = sorted(records, key=lambda row: (row[field], row["id"]))
    assert [row["seed"]["id"] for page in pages for row in page] == [row["id"] for row in expected]
    assert [len(page) for page in pages] == [500, 500, 200]
    assert not reader.metadata["retrieval_truncated"]


def test_cancel_graph_read_terminates_only_its_tagged_transaction(neo4j):
    from concurrent.futures import ThreadPoolExecutor

    from shyhurricane.graph.budget import QueryBudget

    budget = QueryBudget()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(budget.read, neo4j, "UNWIND range(1,1000000000) AS n RETURN sum(n) AS total")
        deadline = time.monotonic() + 10
        found = False
        while time.monotonic() < deadline:
            rows = neo4j.read(
                "SHOW TRANSACTIONS YIELD transactionId,metaData WHERE metaData.graph_request=$id RETURN transactionId",
                timeout=5, id=budget.request_id,
            )
            if rows:
                found = True
                break
            time.sleep(0.02)
        assert found
        budget.cancel()
        with pytest.raises(Exception, match="terminated|cancelled"):
            future.result(timeout=10)
        assert neo4j.read("RETURN 1 AS alive", timeout=5) == [{"alive": 1}]


def test_focused_queries_ignore_tenfold_disconnected_noise(neo4j, event):
    from neo4j import Query

    from shyhurricane.graph.lookup import migrate_lookup, reverse_host

    url = "https://graph-test.invalid/efficient-page"
    graph = extract(event(url=url, body='<input name="value"><a href="/next">next</a>'))
    neo4j.publish(graph)
    migrate_lookup(neo4j, time.monotonic() + 60, threading.Event())
    baseline = None
    trials = []
    read = neo4j.read
    for count in (0, 1000, 10000):
        if count:
            with neo4j.connect().session() as session:
                session.run(
                    "UNWIND range(1,$count) AS i "
                    "MERGE (n:GraphEntity {id:'efficiency-noise-'+toString(i)}) "
                    "SET n.url=$prefix+toString(i),n.kind='resource',n._reverse_host=$host "
                    "MERGE (context:GraphContext {id:'efficiency-context-'+toString(i)}) "
                    "SET context.url=n.url,context.reverse_host=$host,context.owner_kind='GraphEntity',context.owner_id=n.id",
                    count=count, prefix="https://graph-test.invalid/noise/", host=reverse_host(url),
                ).consume()
        hits = []

        def profile(statement, **parameters):
            timeout = parameters.pop("timeout", 10)
            with neo4j.connect().session(default_access_mode="READ") as session:
                result = session.run(Query("PROFILE " + statement, timeout=timeout), **parameters)
                rows = [dict(row) for row in result]
                plan = result.consume().profile

            def total(node):
                return node.get("dbHits", 0) + sum(total(child) for child in node.get("children", []))

            hits.append(total(plan))
            if count == 10000 and total(plan) > 1000:
                def costly(node):
                    if node.get("dbHits", 0) > 1000:
                        print(node["operatorType"], node.get("dbHits"), node.get("args", {}).get("Details", "")[:300])
                    for child in node.get("children", []):
                        costly(child)
                print(statement.split("*/")[0], total(plan))
                costly(plan)
            assert "NodeByLabelScan" not in str(plan) and "AllNodesScan" not in str(plan)
            return rows

        neo4j.read = profile
        started = time.monotonic()
        try:
            actual = GraphQuery(neo4j).elements(url, url=url)
            endpoints = GraphQuery(neo4j).endpoints(url, url=url)
        finally:
            neo4j.read = read
        assert actual["results"] and endpoints["results"]
        assert not actual["retrieval_truncated"] and not endpoints["retrieval_truncated"]
        if baseline is None:
            baseline = (actual["results"], endpoints["results"])
        assert (actual["results"], endpoints["results"]) == baseline
        trials.append({"noise": count, "seconds": time.monotonic() - started, "db_hits": sum(hits)})
    print(json.dumps({"focused_query_trials": trials}))
    assert trials[-1]["db_hits"] <= 2 * trials[1]["db_hits"]
    assert all(trial["seconds"] < 10 for trial in trials)
    print(json.dumps({"focused_query_trials": trials}))
