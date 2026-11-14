"""Durable inventory retries, accepted expansion pins, and immutable detail recipes."""

import json
import sqlite3
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import ServiceUnavailable

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.detail_recipe import resolve
from shyhurricane.graph.expansion_jobs import accept_job
from shyhurricane.graph.expansion_request import reserve
from shyhurricane.graph.inventory_pipeline import InventoryPipeline
from shyhurricane.graph.inventory_updates import deliver, enqueue


def test_pipeline_availability_backoff_and_terminal_status(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    try:
        pipeline = InventoryPipeline(artifacts, MagicMock())
        assert not pipeline.available()
        capture = artifacts.register(event())
        assert pipeline.available()
        with artifacts.connection:
            artifacts.connection.execute("UPDATE graph_inventory_catalog SET after_seq=(SELECT max(seq) FROM captures)")
            artifacts.connection.execute("UPDATE graph_inventory_generations SET state='waiting'")
        assert not pipeline.available()
        unit = artifacts.manifest.unit(capture["id"], "test", discovery="complete", flow="partial")
        generation = artifacts.manifest.generation(unit)
        assert pipeline.available()
        monkeypatch.setattr(pipeline, "_step", MagicMock(side_effect=ServiceUnavailable("offline")))
        assert pipeline.step() and pipeline.retries == 1 and not pipeline.available()
        assert pipeline.step()
        pipeline._step.assert_called_once()
        pipeline.next_attempt = 0

        def fail():
            pipeline.current = generation
            raise ValueError("invalid record")

        monkeypatch.setattr(pipeline, "_step", fail)
        assert pipeline.step()
        assert artifacts.connection.execute(
            "SELECT state FROM graph_inventory_generations WHERE id=?", (generation,)
        ).fetchone() == ("failed",)
        metadata = json.loads(artifacts.connection.execute(
            "SELECT metadata FROM graph_inventory_updates WHERE generation=?", (generation,)
        ).fetchone()[0])
        assert metadata["discovery"] == metadata["flow"] == metadata["materialization"] == "failed"
        assert pipeline.available()
        monkeypatch.setattr(pipeline, "_step", MagicMock(side_effect=ValueError("dataset mismatch")))
        with pytest.raises(ValueError, match="dataset mismatch"):
            pipeline.step()
        monkeypatch.setattr(pipeline, "_step", lambda: False)
        assert not pipeline.step() and pipeline.retries == 0
    finally:
        artifacts.close()


def test_pipeline_dataset_claim(graph_paths):
    artifacts = ArtifactStore("db")
    try:
        pipeline = InventoryPipeline(artifacts, MagicMock())
        session = MagicMock()
        monkey_claim = artifacts.connection.execute("SELECT id FROM graph_dataset").fetchone()[0]
        session.run.return_value.single.return_value = {"version": 1}
        tx = MagicMock()
        tx.run.return_value.single.return_value = {"id": "different"}
        session.execute_write.side_effect = lambda fn: fn(tx)
        with pytest.raises(ValueError, match="different assessments"):
            pipeline.initialize(session)
        tx.run.return_value.single.return_value = {"id": monkey_claim}
        pipeline.initialize(session)
        assert pipeline.ready
        before = session.run.call_count
        pipeline.initialize(session)
        assert session.run.call_count == before
    finally:
        artifacts.close()


def test_capture_registration_rolls_back_with_publication_obligation(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = event()
    try:
        original = artifacts.manifest.outbox.enqueue
        monkeypatch.setattr(artifacts.manifest.outbox, "enqueue", MagicMock(side_effect=OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            artifacts.register(capture)
        assert not artifacts.connection.execute("SELECT 1 FROM captures").fetchone()
        assert not artifacts.connection.execute("SELECT 1 FROM graph_inventory_outbox").fetchone()
        monkeypatch.setattr(artifacts.manifest.outbox, "enqueue", original)
        assert artifacts.register(capture)["id"] == capture["id"]
        assert artifacts.connection.execute("SELECT count(*) FROM graph_inventory_outbox").fetchone() == (1,)
        assert artifacts.register(capture)["id"] == capture["id"]
        assert artifacts.connection.execute("SELECT count(*) FROM graph_inventory_outbox").fetchone() == (1,)
    finally:
        artifacts.close()


def test_published_generation_status_does_not_append_or_replace_inventory(graph_paths, event):
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event())
        artifact = artifacts.write("ir", {"nodes": []})
        unit = artifacts.manifest.unit(capture["id"], "immutable", discovery="complete", artifact=artifact)
        generation = artifacts.manifest.generation(unit)
        with artifacts.connection:
            artifacts.connection.execute("UPDATE graph_inventory_generations SET state='active' WHERE id=?", (generation,))
        before = artifacts.connection.execute("SELECT count(*) FROM graph_inventory_outbox").fetchone()[0]
        assert artifacts.manifest.unit(capture["id"], "immutable", discovery="failed", flow="failed", error="failure") == unit
        assert artifacts.connection.execute("SELECT count(*) FROM graph_inventory_outbox").fetchone()[0] == before
        with pytest.raises(ValueError, match="immutable"):
            artifacts.manifest.unit(capture["id"], "immutable", artifact=artifacts.write("other", {"changed": True}))
        with pytest.raises(ValueError, match="unavailable"):
            artifacts.manifest.set_status("missing")
        with pytest.raises(ValueError, match="coverage status"):
            artifacts.manifest.set_status(unit, flow="unknown")
        orphan = artifacts.manifest.unit("missing-capture", "execution-only")
        artifacts.manifest.set_status(orphan, materialization="complete")
    finally:
        artifacts.close()


def test_status_remote_commit_precedes_local_ack(graph_paths, event):
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event())
        unit = artifacts.manifest.unit(capture["id"], "test", discovery="complete", flow="partial")
        generation = artifacts.manifest.generation(unit)
        with artifacts.connection:
            enqueue(artifacts.connection, unit, None, "pending")
            enqueue(artifacts.connection, unit, generation, "pending")
        with pytest.raises(ValueError, match="unavailable"):
            enqueue(artifacts.connection, unit, "missing", "pending")
        row = artifacts.connection.execute("SELECT unit_id,generation,version,metadata FROM graph_inventory_updates").fetchone()
        session, tx = MagicMock(), MagicMock()
        tx.run.return_value.single.side_effect = [None, {"revision": 7}, {"id": "already published"}]
        session.execute_write.side_effect = lambda fn: fn(tx)
        deliver(session, artifacts.connection, row)
        artifacts.connection.rollback()
        assert artifacts.connection.execute("SELECT delivered FROM graph_inventory_updates").fetchone()[0] == 0
        with artifacts.connection:
            deliver(session, artifacts.connection, row)
        assert artifacts.connection.execute("SELECT delivered FROM graph_inventory_updates").fetchone()[0] == 1
    finally:
        artifacts.close()


def test_expansion_acceptance_pins_artifact_before_wakeup_and_survives_reopen(graph_paths, event, monkeypatch):
    monkeypatch.setattr("shyhurricane.graph.expansion_request.persistent_queue_path", lambda *args: graph_paths / "graph_state")
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    path = artifacts.write("detail", {"nodes": [], "edges": []})
    unit = artifacts.manifest.unit(capture["id"], "detail", discovery="complete", flow="partial", artifact=path)
    generation = artifacts.manifest.generation(unit)
    item = {"id": capture["id"], "analysis_unit_id": unit, "inventory_generation": generation,
            "inventory_artifact": path}
    reserve("db", item, QueryBudget())
    reserve("db", item)
    assert artifacts.connection.execute("SELECT count(*) FROM graph_expansions").fetchone() == (1,)
    assert artifacts.connection.execute("SELECT count(*) FROM graph_expansion_receipts").fetchone() == (0,)
    with artifacts.connection:
        key = accept_job(artifacts.connection, item, 42)
        artifacts.connection.execute("UPDATE graph_expansions SET state='failed'")
        assert accept_job(artifacts.connection, item, 43) == key
    assert artifacts.connection.execute("SELECT state,artifact FROM graph_expansions").fetchone() == ("pending", path)
    with artifacts.connection:
        artifacts.connection.execute("UPDATE graph_expansions SET state='done'")
        version = artifacts.connection.execute("SELECT version FROM graph_inventory_updates").fetchone()[0]
        assert accept_job(artifacts.connection, item, None) == key
        assert artifacts.connection.execute("SELECT version FROM graph_inventory_updates").fetchone()[0] == version
    assert artifacts.connection.execute(
        "SELECT count(*) FROM graph_object_owners WHERE ref=? AND owner LIKE 'graph_expansions:artifact:%'", (path,)
    ).fetchone() == (1,)
    artifacts.close()
    artifacts = ArtifactStore("db")
    try:
        assert artifacts.read(path) == {"nodes": [], "edges": []}
        assert artifacts.connection.execute("SELECT count(*) FROM graph_expansion_receipts").fetchone() == (2,)
        budget = QueryBudget(seconds=0)
        with pytest.raises(TimeoutError):
            reserve("db", {**item, "analysis_unit_id": "new"}, budget)
        with artifacts.connection:
            artifacts.connection.execute("BEGIN IMMEDIATE")
            with pytest.raises(sqlite3.OperationalError):
                reserve("db", item)
            budget = QueryBudget(seconds=0.1)
            with pytest.raises(TimeoutError):
                reserve("db", item, budget)
    finally:
        artifacts.close()


def test_detail_recipes_preserve_endpoints_ids_and_contexts():
    raw = {"nodes": [{"id": key} for key in ("a", "b", "c")], "edges": [
        {"source": "a", "target": "b"}, {"source": "b", "target": "c"}], "gaps": ["gap"]}
    artifacts = MagicMock()
    artifacts.read.side_effect = lambda key: {"raw": raw, "edge": {"ir_artifact": "raw", "edge_offset": 1, "edge_limit": 1}}[key]
    result = resolve(artifacts, {"ir_artifact": "edge", "contexts": ["context"], "filename": "app.js"})
    assert result["nodes"] == [{"id": "b"}, {"id": "c"}] and result["edges"] == raw["edges"][1:]
    assert result["gaps"] == ["gap"] and result["contexts"] == ["context"] and result["filename"] == "app.js"
    result = resolve(artifacts, {"ir_artifact": "raw", "node_ids": ["a", "missing"], "contexts": [], "requires_context_shards": True})
    assert result["nodes"] == [{"id": "a"}] and result["edges"] == [] and result["requires_context_shards"]
    for descriptor in ({"edge_offset": -1, "edge_limit": 1}, {"edge_offset": 0, "edge_limit": 2001},
                       {"edge_offset": "0", "edge_limit": 1}, {"node_ids": "a"}, {"node_ids": ["a"] * 2001}):
        with pytest.raises(ValueError):
            resolve(artifacts, {"ir_artifact": "raw", **descriptor})
    artifacts.read.side_effect = lambda key: {"ir_artifact": key}
    with pytest.raises(ValueError, match="recursive"):
        resolve(artifacts, {"ir_artifact": "loop"})
