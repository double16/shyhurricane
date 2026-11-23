"""Fresh-storage publication and public discovery contracts against dedicated Neo4j."""

import json
import os
from uuid import uuid4

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.inventory_pipeline import InventoryPipeline
from shyhurricane.graph.query import GraphQuery

pytestmark = pytest.mark.skipif(not os.environ.get("GRAPH_INVENTORY_TEST_URI"),
                                reason="Requires a dedicated fresh inventory Neo4j")


def drain(pipeline):
    for _ in range(1000):
        if not pipeline.step():
            return
    pytest.fail("Inventory publication did not drain")


def test_markup_history_context_and_continuation(graph_paths, event, inventory_database, caplog):
    import logging

    caplog.set_level(logging.INFO)
    host = uuid4().hex + ".example.com"
    url = "https://" + host + "/page"
    artifacts = ArtifactStore("db")
    store = inventory_database
    try:
        store.ready()
        capture = artifacts.register(event(url=url, body='<form action="/save"><input name="first"><input name="second"></form>'))
        extract(capture, artifacts)
        pipeline = InventoryPipeline(artifacts, store)
        drain(pipeline)
        query = GraphQuery(store, artifacts=artifacts)
        result = query.elements(host, kinds=["field"], detail="full")
        assert {row["name"] for row in result["results"]} == {"first", "second"}
        assert result["coverage"]["discovery"] == "complete"
        assert not result["retrieval_truncated"]
        assert artifacts.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='graph_facts'"
        ).fetchone() is None
        resources = query.endpoints(host)
        assert any(row["url"] == "https://" + host + "/save" for row in resources["results"])
        watermark = artifacts.manifest.watermark()
        newer = artifacts.register(event(url=url, body='<input name="new">',
                                         timestamp="2026-02-01T00:00:00Z"))
        extract(newer, artifacts)
        drain(pipeline)
        latest, _ = artifacts.manifest.page(host, kind="field")
        assert {row["name"] for row in latest} == {"new"}
        previous, _ = artifacts.manifest.page(host, kind="field", watermark=watermark)
        assert {row["name"] for row in previous} == {"first", "second"}
        historical, _ = artifacts.manifest.page(host, kind="field", historical=True)
        assert {"first", "second", "new"} <= {row["name"] for row in historical}
        as_of, _ = artifacts.manifest.page(host, kind="field", as_of=capture["observed_at"])
        assert {row["name"] for row in as_of} == {"first", "second"}
        with pytest.raises(ValueError):
            artifacts.manifest.page(host, limit=0)
        from test_performance import summaries

        metrics = summaries(caplog, "inventory_publish")
        assert {row["stage"] for row in metrics} >= {"catalog", "facts", "activation"}
        batches = [row for row in metrics if row["stage"] == "facts"]
        assert all(row["records"] > 0 and row["delivery"] == "write" for row in batches)
        assert all({"neo4j_write", "sqlite_ack", "sqlite_commit"} <= row["phase_seconds"].keys() for row in batches)
        assert all(row["batch_id"] and row["shard_id"] and row["sequence"] >= 0 for row in batches)
        assert not any(host in json.dumps(row) for row in metrics)
    finally:
        artifacts.close()
        store.close()


def test_epoch_drains_inventory_and_publishes_status(graph_paths, event, inventory_database):
    from shyhurricane.graph.epochs import Epochs, epoch_status

    artifacts = ArtifactStore("db")
    engine = Epochs(artifacts, inventory_database)
    try:
        engine.accept(event(body='<form action="/save"><input name="value"></form>'), 1)
        for _ in range(500):
            if not engine.available():
                break
            engine.step()
        else:
            pytest.fail("Epoch failed to drain")
        assert epoch_status(artifacts.connection)["phase"] == "done"
        assert not artifacts.connection.execute(
            "SELECT 1 FROM graph_inventory_generations WHERE state='pending'"
        ).fetchone()
        query = GraphQuery(inventory_database, artifacts=artifacts)
        assert {row["name"] for row in query.elements("example.com", kinds=["field"])["results"]} == {"value"}
        from shyhurricane.graph.model import capture_unit_path

        units = query.elements("example.com", kinds=["analysis_unit"], detail="full")["results"]
        capture = artifacts.latest("https://example.com/page")
        assert next(row for row in units if row["source_path"] == capture_unit_path(capture))["materialization"] == "complete"
    finally:
        engine.close()
        artifacts.close()


def test_scope_context_membership_oversized_and_capture_status(graph_paths, event, inventory_database):
    artifacts = ArtifactStore("db")
    try:
        document = artifacts.register(event(url="https://app.example.com:8443/page"))
        script = artifacts.register(event(url="https://cdn.example.com/app.js", mime="text/javascript"))
        unit = artifacts.manifest.unit(script["id"], "script", discovery="complete", flow="partial")
        artifacts.manifest.contexts(unit, [{"id": document["id"], "url": document["data"]["url"]}])
        artifacts.manifest.fact(unit, script["id"], "field", {"id": "field", "name": "cross-origin", "url": script["data"]["url"]})
        artifacts.manifest.fact(unit, script["id"], "resource", {
            "id": "huge", "url": "https://app.example.com:8443/api", "method": "POST", "detail": "x" * (4 * 1024 * 1024),
        })
        pipeline = InventoryPipeline(artifacts, inventory_database)
        drain(pipeline)
        GraphQuery(inventory_database, artifacts=artifacts)
        rows, _ = artifacts.manifest.page("https://app.example.com:8443/page", kind="field")
        assert [row["name"] for row in rows] == ["cross-origin"]
        assert artifacts.manifest.page("https://app.example.com:9443/page", kind="field")[0] == []
        rows, _ = artifacts.manifest.page("app.example.com:8443", kind="resource", method="post")
        assert rows[0]["oversized"] and rows[0]["capture_status"] == "referenced"
        assert rows[0]["follow_up"]["arguments"]["url"].endswith("/api")
        pin = artifacts.manifest.watermark()
        artifacts.register(event(url="https://app.example.com:8443/api", method="POST"))
        drain(pipeline)
        assert artifacts.manifest.page("app.example.com:8443", kind="resource", method="POST")[0][0]["capture_status"] == "captured"
        assert artifacts.manifest.page("app.example.com:8443", kind="resource", method="POST", watermark=pin)[0][0]["capture_status"] == "referenced"
        # A replacement document must remove old contextual membership from current selection.
        artifacts.register(event(url=document["data"]["url"], timestamp="2026-02-01T00:00:00Z"))
        drain(pipeline)
        assert artifacts.manifest.page("https://app.example.com:8443/page", kind="field")[0] == []
        assert artifacts.manifest.page("https://app.example.com:8443/page", kind="field", historical=True)[0]
    finally:
        artifacts.close()


def test_context_publication_is_bounded_and_resumes_after_reopen(graph_paths, event, inventory_database):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "contexts", discovery="complete")
    artifacts.manifest.contexts(unit, [{"id": str(index), "url": f"https://example.com/doc/{index}"}
                                     for index in range(501)])
    generation = artifacts.manifest.generation(unit)
    pipeline = InventoryPipeline(artifacts, inventory_database)
    for _ in range(20):
        pipeline.step()
        after, state = artifacts.connection.execute(
            "SELECT context_after,state FROM graph_inventory_generations WHERE id=?", (generation,)
        ).fetchone()
        if after:
            assert state == "pending"
            break
    else:
        pytest.fail("Context publication did not begin")
    with inventory_database.connect().session() as session:
        assert session.run(
            "MATCH (c:GraphInventoryContext {generation:$generation}) RETURN count(c) AS count",
            generation=generation,
        ).single()["count"] == 500
    artifacts.close()
    artifacts = ArtifactStore("db")
    try:
        pipeline = InventoryPipeline(artifacts, inventory_database)
        assert pipeline.step()
        assert artifacts.connection.execute(
            "SELECT state FROM graph_inventory_generations WHERE id=?", (generation,)
        ).fetchone() == ("pending",)
        drain(pipeline)
        with inventory_database.connect().session() as session:
            assert session.run(
                "MATCH (c:GraphInventoryContext {generation:$generation}) RETURN count(c) AS count",
                generation=generation,
            ).single()["count"] == 501
    finally:
        artifacts.close()


def test_parser_failure_updates_published_coverage_without_extra_batches(graph_paths, event, inventory_database, monkeypatch):
    from unittest.mock import MagicMock

    from shyhurricane.graph.epochs import Epochs, epoch_status

    artifacts = ArtifactStore("db")
    engine = Epochs(artifacts, inventory_database)
    try:
        engine.accept(event(body="failure fixture"), 1)
        monkeypatch.setattr(engine, "parse", MagicMock(side_effect=ValueError("parser failure")))
        for _ in range(100):
            if not engine.available():
                break
            engine.step()
        else:
            pytest.fail("Failed epoch did not settle")
        assert epoch_status(artifacts.connection)["failed"] == 1
        query = GraphQuery(inventory_database, artifacts=artifacts)
        result = query.elements("example.com", kinds=["analysis_unit"], detail="full")
        assert result["coverage"]["discovery"] == "failed"
        assert result["results"][0]["discovery"] == "failed"
        assert result["results"][0]["error"] == "parser failure"
        assert artifacts.connection.execute(
            "SELECT count(*) FROM graph_inventory_outbox WHERE state='pending'"
        ).fetchone() == (0,)
    finally:
        engine.close()
        artifacts.close()
