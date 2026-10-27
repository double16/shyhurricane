"""Real Neo4j publication and idle regressions, using an isolated test server."""

import os
import threading
import time

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.database import GraphStore
from shyhurricane.graph.epochs import Epochs, epoch_status
from shyhurricane.graph.extract import extract
from shyhurricane.graph.link_publication import LinkPublisher
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import Projection
from shyhurricane.graph.visibility import visible_relationship

pytestmark = pytest.mark.skipif(not os.environ.get("NEO4J_TEST_URI"), reason="Requires isolated Neo4j test instance")
PREFIX = "https://example.com/epoch-regression/"


def test_detail_unit_is_idempotent_visible_and_retains_pinned_generations(database, event):
    from shyhurricane.graph.model import identity
    from shyhurricane.graph.publication import GraphPublisher
    from shyhurricane.graph.query import GraphQuery
    from shyhurricane.graph.unit_publication import UnitPublisher

    capture = event(url=PREFIX + "detail.js")
    base = Projection(capture)
    base.resource(base.url)
    base.planned_links = {}
    database.publish(base)
    projection = Projection(capture)
    source = projection.node("symbol", "detail-source", role="source", capture_id=capture["id"])
    sink = projection.node("symbol", "detail-sink", role="sink", capture_id=capture["id"])
    projection.fact(source, sink, "FLOWS_TO", "fixture.flow")
    projection.planned_links = {}
    publisher = UnitPublisher(database, identity("detail-unit"))
    assert publisher.publish(projection)
    assert not publisher.publish(projection)
    query = GraphQuery(database)
    result = query.paths("example.com", source, end=sink, mode="flow")
    assert result["results"]
    revision = database.read("MATCH (r:GraphState {id:'publication_revision'}) RETURN r.value AS value")[0]["value"]
    query.pin_query("fixture-pin", revision)
    projection.gaps.append("changed fixture")
    # Change semantic detail, retire its first generation, then make cleanup immediately eligible.
    projection.node("symbol", "another-operation", capture_id=capture["id"])
    publisher.publish(projection)
    with database.connect().session(database="neo4j") as session:
        session.run("MATCH (p:GraphPublication) WHERE p.analysis_unit_id=$unit AND p.state='retired' "
                    "SET p.retired_at=0", unit=publisher.unit_id).consume()
    GraphPublisher(database).cleanup()
    assert database.read("MATCH (p:GraphReadPin {id:$id}) RETURN p.revision AS revision",
                         id=identity("fixture-pin"))[0]["revision"] == revision
    old = database.read("MATCH (p:GraphPublication {analysis_unit_id:$unit,state:'retired'}) "
                        "RETURN p.cleaned AS cleaned", unit=publisher.unit_id)
    assert old and not old[0]["cleaned"]
    with database.connect().session(database="neo4j") as session:
        session.run("MATCH (p:GraphReadPin {id:$id}) DELETE p", id=identity("fixture-pin")).consume()


def test_expansion_can_recover_detail_when_base_capture_analysis_failed(database, event):
    from shyhurricane.graph.model import identity
    from shyhurricane.graph.query import GraphQuery
    from shyhurricane.graph.unit_publication import UnitPublisher

    projection = Projection(event(url=PREFIX + "recovered-detail.js"))
    source = projection.node("symbol", "recovered-source", role="source", capture_id=projection.event["id"])
    sink = projection.node("symbol", "recovered-sink", role="sink", capture_id=projection.event["id"])
    projection.fact(source, sink, "FLOWS_TO", "fixture.flow")
    projection.planned_links = {}
    assert UnitPublisher(database, identity("recovered-unit")).publish(projection)
    result = GraphQuery(database).paths("example.com", source, end=sink, mode="flow")
    assert result["results"]
    row = database.read("MATCH (c:GraphCapture {id:$id}) RETURN c.unit_only AS partial", id=projection.event["id"])
    assert row[0]["partial"]


@pytest.fixture
def database():
    store = GraphStore(os.environ["NEO4J_TEST_URI"])
    store.ready()

    def clean():
        with store.connect().session(database="neo4j") as session:
            while session.run(
                "MATCH (n) WHERE n.url STARTS WITH $prefix WITH n LIMIT 100 DETACH DELETE n RETURN count(*) AS n",
                prefix=PREFIX,
            ).single()["n"]:
                pass

    clean()
    try:
        yield store
    finally:
        clean()
        store.close()


def test_inferred_link_generations_keep_structural_ids_and_evidence(database, event):
    page = extract(event(url=PREFIX + "page", body='<input id="field" name="field">'))
    page.planned_links = {}
    database.publish(page)
    script = Projection(event(url=PREFIX + "script.js"))
    script.library_analysis = "summary"
    script.contexts = [{"id": page.event["id"], "url": page.url, "base": page.url}]
    root = script.resource(script.url)
    node = script.node("symbol", "selector", capture_id=script.event["id"], selector="#field")
    script.fact(root, node, "CONTAINS", "test.symbol")
    script.planned_links = {}
    database.publish(script)
    before = database.read(
        "MATCH (c:GraphCapture) WHERE c.url STARTS WITH $prefix "
        "RETURN c.id AS id,c.active_publication_id AS generation ORDER BY id", prefix=PREFIX,
    )
    script.planned_links = LinkPlanner(database, script).plan()
    assert script.planned_links
    publisher = LinkPublisher(database)
    assert publisher.publish(script)
    assert not publisher.publish(script)
    assert database.read(
        "MATCH (c:GraphCapture) WHERE c.url STARTS WITH $prefix "
        "RETURN c.id AS id,c.active_publication_id AS generation ORDER BY id", prefix=PREFIX,
    ) == before
    rows = database.read(
        "MATCH (a:GraphEntity)-[r:RELATES]->(b:GraphEntity) WHERE r._link_publication=true "
        f"AND a.url STARTS WITH $prefix AND {visible_relationship('r')} "
        "MATCH (e:GraphEvidence {id:r.evidence_id}) RETURN r.id AS id,e.id AS evidence", prefix=PREFIX,
    )
    assert rows
    # Retire the old link generation by publishing a different complete link set.
    script.planned_links = {}
    assert publisher.publish(script)
    with database.connect().session(database="neo4j") as session:
        session.run(
            "MATCH (p:GraphPublication) WHERE p.url STARTS WITH $prefix AND p.state='retired' SET p.retired_at=0",
            prefix=PREFIX,
        ).consume()
    for _ in range(3):
        database.cleanup(deadline=time.monotonic() + 30, stop_event=threading.Event())
    assert database.read(
        "MATCH (n:GraphEntity) WHERE n.url STARTS WITH $prefix RETURN n.id AS id", prefix=PREFIX,
    )
    assert not database.read(
        "MATCH ()-[r:RELATES]->() WHERE r.id IN $ids RETURN r.id AS id", ids=[row["id"] for row in rows],
    )
    assert database.read(
        "MATCH (e:GraphEvidence) WHERE e.id IN $ids RETURN e.id AS id", ids=[row["evidence"] for row in rows],
    )


def test_400_captures_80_urls_drain_and_two_maintenance_cycles_stay_idle(database, graph_paths, event):
    artifacts = ArtifactStore("db")
    engine = Epochs(artifacts, database)
    try:
        for index in range(400):
            capture = artifacts.register(event(
                url=f"{PREFIX}{index % 80}", body=f'<a href="{PREFIX}{(index + 1) % 80}">{index}</a>',
            ))
            engine.accept(capture, index)
        for _ in range(5000):
            if not engine.available():
                break
            engine.step()
        status = epoch_status(artifacts.connection)
        assert status["phase"] == "done" and status["completed"] == 400
        assert status["structural_activations"] == status["link_activations"] == 400
        revision = database.activity()["publication_revision"]
        count = database.read(
            "MATCH (n) WHERE n.url STARTS WITH $prefix RETURN count(n) AS n", prefix=PREFIX,
        )
        for _ in range(2):
            engine.step()
            database.cleanup(deadline=time.monotonic() + 30, stop_event=threading.Event())
        assert not engine.available()
        assert database.activity()["publication_revision"] == revision
        assert database.read(
            "MATCH (n) WHERE n.url STARTS WITH $prefix RETURN count(n) AS n", prefix=PREFIX,
        ) == count
    finally:
        engine.close()
        artifacts.close()
