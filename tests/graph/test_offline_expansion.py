"""Offline shard publication and terminal failures preserve durable queue receipts."""

import json
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import ServiceUnavailable

from shyhurricane.graph import expansion
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.discovery_manifest import archive_ir
from shyhurricane.graph.expansion import Expansions
from shyhurricane.graph.model import Projection, projection_snapshot
from shyhurricane.graph.publication import PublicationConflict
from shyhurricane.graph.unit_publication import UnitPublisher


@pytest.mark.parametrize("snapshot", [False, True])
def test_expansion_publishes_retained_artifact_once_and_settles(graph_paths, event, monkeypatch, snapshot):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(mime="text/javascript", body="const a=1"))
    unit = archive_ir(artifacts, capture, capture["data"]["url"], "app.js", {
        "nodes": [{"id": "a", "kind": "symbol", "name": "a"}], "edges": [], "gaps": [],
        "references": [{"url": "/save", "kind": "REQUESTS", "source": "a"}],
    }, contexts=[{"id": "document", "url": "https://example.com/", "base": "https://example.com/"}])
    if snapshot:
        path = artifacts.write("projection", projection_snapshot(Projection(capture)))
        artifacts.connection.execute("UPDATE graph_manifest_units SET artifact=? WHERE id=?", (path.name, unit))
        artifacts.connection.commit()
    publish = MagicMock()
    monkeypatch.setattr(expansion.UnitPublisher, "publish", publish)
    jobs = Expansions(artifacts, MagicMock())
    item = {**capture, "analysis_unit_id": unit}
    jobs.accept(item, 1)
    jobs.accept(item, 2)
    assert jobs.available() and jobs.step() and not jobs.step()
    assert not jobs.available()
    publish.assert_called_once()
    assert artifacts.connection.execute("SELECT materialization FROM graph_manifest_units WHERE id=?",
                                        (unit,)).fetchone()[0] == "complete"
    queue = MagicMock()
    jobs.settle(queue)
    assert queue.ack.call_count == 2
    jobs.settle(queue)
    assert queue.ack.call_count == 2
    artifacts.close()


@pytest.mark.parametrize("failure", [ValueError("invalid"), ServiceUnavailable("retry")])
def test_expansion_failure_is_durable_and_retryable(graph_paths, event, monkeypatch, failure):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    path = artifacts.write("retained", projection_snapshot(Projection(capture)))
    unit = artifacts.manifest.unit(capture["id"], "fixture", artifact=path.name)
    monkeypatch.setattr(expansion.UnitPublisher, "publish", MagicMock(side_effect=failure))
    jobs = Expansions(artifacts, MagicMock())
    item = {**capture, "analysis_unit_id": unit}
    jobs.accept(item, 1)
    assert jobs.step()
    assert not jobs.available()
    state, error = artifacts.connection.execute("SELECT state,error FROM graph_expansions").fetchone()
    assert state == ("pending" if isinstance(failure, ServiceUnavailable) else "failed")
    assert str(failure) in error
    queue = MagicMock()
    jobs.settle(queue)
    assert queue.ack_failed.call_count == int(state == "failed")
    if state == "failed":
        jobs.accept(item, 3)
        assert artifacts.connection.execute("SELECT state FROM graph_expansions").fetchone()[0] == "pending"
    artifacts.close()


def test_missing_unit_fails_original_receipt(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    jobs = Expansions(artifacts, MagicMock())
    jobs.accept({**capture, "analysis_unit_id": "missing"}, 1)
    jobs.step()
    queue = MagicMock()
    jobs.settle(queue)
    queue.ack_failed.assert_called_once_with(id=1)
    artifacts.close()


@pytest.mark.parametrize("oversized", [False, True])
def test_deferred_source_is_parsed_offline_and_oversized_raw_units_require_shards(
    graph_paths, event, monkeypatch, oversized
):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    raw = {"nodes": [{"id": str(index), "kind": "symbol"} for index in range(4001)], "edges": []} if oversized else {
        "source": "eval(location.hash)", "filename": "fixture.js", "contexts": [],
    }
    path = artifacts.write("raw", raw)
    unit = artifacts.manifest.unit(capture["id"], "fixture.js", artifact=path.name)
    runner = MagicMock(return_value={"nodes": [], "edges": [], "references": [], "gaps": []})
    monkeypatch.setattr("shyhurricane.graph.extract.run_javascript", runner)
    monkeypatch.setattr(expansion.UnitPublisher, "publish", MagicMock())
    jobs = Expansions(artifacts, MagicMock())
    jobs.accept({**capture, "analysis_unit_id": unit}, 1)
    jobs.step()
    state, error = artifacts.connection.execute("SELECT state,error FROM graph_expansions").fetchone()
    assert state == ("failed" if oversized else "done")
    assert runner.call_count == int(not oversized)
    if oversized:
        assert "shard" in error
    artifacts.close()


@pytest.mark.parametrize("complete", [True, False])
def test_unit_publication_has_independent_ownership_and_validation(event, monkeypatch, complete):
    graph = Projection(event())
    graph.resource(graph.url)
    publisher = UnitPublisher(MagicMock(), "unit")
    monkeypatch.setattr("shyhurricane.graph.links.LinkPlanner.plan", lambda self: {})
    monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", complete))
    stage, activate, validate = MagicMock(), MagicMock(), MagicMock()
    monkeypatch.setattr(publisher, "stage", stage)
    monkeypatch.setattr(publisher, "activate", activate)
    monkeypatch.setattr(publisher, "validate_dependencies", validate)
    assert publisher.publish(graph) is not complete
    assert stage.call_count == activate.call_count == validate.call_count == int(not complete)
    if not complete:
        assert all(node["_unit_id"] == "unit" for node in graph.nodes.values())


def test_unit_activation_conflict_abandons_staging(event, monkeypatch):
    publisher = UnitPublisher(MagicMock(), "unit")
    monkeypatch.setattr("shyhurricane.graph.links.LinkPlanner.plan", lambda self: {})
    monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", False))
    monkeypatch.setattr(publisher, "stage", MagicMock(side_effect=PublicationConflict("changed")))
    abandon = MagicMock(side_effect=OSError("offline"))
    monkeypatch.setattr(publisher, "abandon", abandon)
    with pytest.raises(PublicationConflict):
        publisher.publish(Projection(event()))
    abandon.assert_called_once()


def test_unit_metadata_transactions_compare_and_switch_pointer():
    publisher = UnitPublisher(MagicMock(), "unit")
    session, tx = MagicMock(), MagicMock()
    session.execute_write.side_effect = lambda action: action(tx)
    tx.run.return_value.single.return_value = {"active": "previous", "digest": "same"}
    assert publisher.begin(session, {"id": "capture"}, "same") == ("previous", True)
    generation, complete = publisher.begin(session, {"id": "capture"}, "different")
    assert not complete
    assert tx.run.call_args.kwargs["metadata"]["id"] == generation
    publisher.activate(session, {"id": "capture"}, generation)
    assert "u.active_publication_id=p.id" in tx.run.call_args.args[0]
    tx.run.return_value.single.return_value = None
    with pytest.raises(PublicationConflict):
        publisher.activate(session, {"id": "capture"}, generation)


def test_expansion_planning_yields_and_resumes_a_durable_checkpoint(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    path = artifacts.write("projection", projection_snapshot(Projection(capture)))
    unit = artifacts.manifest.unit(capture["id"], "fixture", artifact=path.name)
    planner = MagicMock(links={})
    planner.plan_slice.side_effect = [False, True]
    planner.checkpoint.return_value = {}
    monkeypatch.setattr(expansion, "LinkPlanner", lambda *args: planner)
    publish = MagicMock()
    monkeypatch.setattr(expansion.UnitPublisher, "publish", publish)
    jobs = Expansions(artifacts, MagicMock())
    jobs.accept({**capture, "analysis_unit_id": unit}, 1)
    assert jobs.step() and jobs.available()
    publish.assert_not_called()
    checkpoint = artifacts.connection.execute("SELECT checkpoint FROM graph_expansions").fetchone()[0]
    assert artifacts.resolve(checkpoint).exists()
    assert jobs.step() and not jobs.available()
    planner.restore.assert_called_once_with({})
    publish.assert_called_once()
    assert not artifacts.resolve(checkpoint).exists()
    artifacts.close()


def test_large_context_sets_have_bounded_addressable_shards(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    contexts = [{"id": str(index), "url": f"https://example.com/{index}", "base": "https://example.com/"}
                for index in range(205)]
    raw = {"nodes": [{"id": str(index), "kind": "symbol"} for index in range(2050)], "edges": [], "gaps": []}
    unit = archive_ir(artifacts, capture, capture["data"]["url"], "fixture.js", raw, contexts=contexts)
    original = artifacts.connection.execute("SELECT artifact FROM graph_manifest_units WHERE id=?", (unit,)).fetchone()[0]
    assert len(json.loads(artifacts.resolve(original).read_text())["nodes"]) == 2050
    shards = artifacts.connection.execute(
        "SELECT id,artifact FROM graph_manifest_units WHERE source_path LIKE '%#context-shard=%' ORDER BY source_path"
    ).fetchall()
    assert len(shards) == 6
    assert all(len(json.loads(artifacts.resolve(row[1]).read_text())["contexts"]) <= 100 for row in shards)
    monkeypatch.setattr(expansion.UnitPublisher, "publish", MagicMock())
    planner = MagicMock(links={})
    planner.plan_slice.return_value = True
    planner.checkpoint.return_value = {}
    monkeypatch.setattr(expansion, "LinkPlanner", lambda *args: planner)
    jobs = Expansions(artifacts, MagicMock())
    parent = artifacts.connection.execute(
        "SELECT id FROM graph_manifest_units WHERE source_path='fixture.js#node-shard=0'"
    ).fetchone()[0]
    jobs.accept({**capture, "analysis_unit_id": parent}, 1)
    jobs.step()
    assert artifacts.connection.execute("SELECT state FROM graph_expansions").fetchone()[0] == "failed"
    jobs.accept({**capture, "analysis_unit_id": shards[0][0]}, 2)
    jobs.step()
    assert artifacts.connection.execute("SELECT state FROM graph_expansions WHERE unit_id=?",
                                        (shards[0][0],)).fetchone()[0] == "done"
    artifacts.close()


def test_markup_expansion_uses_supervised_local_capture_window(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(body='<form action="/save"><input name="value"></form>'))
    from shyhurricane.graph.extract import extract

    extract(capture, artifacts)
    unit = artifacts.connection.execute(
        "SELECT id FROM graph_manifest_units WHERE source_path LIKE '%#markup-shard=0'"
    ).fetchone()[0]
    parser = MagicMock(return_value=Projection(capture))
    monkeypatch.setattr("shyhurricane.graph.parser_worker.parse", parser)
    monkeypatch.setattr(expansion.UnitPublisher, "publish", MagicMock())
    jobs = Expansions(artifacts, MagicMock())
    jobs.accept({**capture, "analysis_unit_id": unit}, 1)
    jobs.step()
    assert artifacts.connection.execute("SELECT state FROM graph_expansions").fetchone()[0] == "done"
    assert parser.call_args.kwargs == {"markup_offset": 0, "markup_limit": 1000,
                                      "record_discovery": False, "open_world": False}
    artifacts.close()


def test_unit_retry_digest_ignores_staging_ownership_tags(event, monkeypatch):
    projection = Projection(event())
    left, right = projection.resource("https://example.com/a"), projection.resource("https://example.com/b")
    projection.fact(left, right, "FLOWS_TO", "fixture.flow")
    projection.planned_links = {"link": {"id": "link"}}
    publisher = UnitPublisher(MagicMock(), "unit")
    begin = MagicMock(return_value=("generation", False))
    monkeypatch.setattr(publisher, "begin", begin)
    monkeypatch.setattr(publisher, "stage", MagicMock())
    monkeypatch.setattr(publisher, "validate_dependencies", MagicMock())
    monkeypatch.setattr(publisher, "activate", MagicMock())
    monkeypatch.setattr("shyhurricane.graph.link_publication.LinkPublisher.validate_staging", MagicMock())
    publisher.publish(projection)
    publisher.publish(projection)
    assert begin.call_args_list[0].args[2] == begin.call_args_list[1].args[2]
    session, tx = MagicMock(), MagicMock()
    session.execute_write.side_effect = lambda action: action(tx)
    tx.run.return_value.single.return_value = {"active": "previous", "digest": "old", "staging": "interrupted"}
    UnitPublisher(MagicMock(), "unit").begin(session, {"id": "capture"}, "new")
    assert any("GraphCleanupPending" in call.args[0] for call in tx.run.call_args_list)
    publisher.abandon(session, "generation")
    assert "u.staging_publication_id=null" in session.run.call_args.args[0]
