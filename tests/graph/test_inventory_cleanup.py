"""Remote cleanup respects revisions and confirms tombstones before releasing local pins."""

import time
from unittest.mock import MagicMock

import pytest
from test_inventory_pipeline import drain

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.inventory_cleanup import InventoryCleanup
from shyhurricane.graph.inventory_pipeline import InventoryPipeline
from shyhurricane.graph.query import GraphQuery


def test_missing_database_and_expired_budget_do_no_work(tmp_path):
    store = MagicMock()
    cleanup = InventoryCleanup(store, tmp_path / "missing.sqlite")
    assert not cleanup.step()
    cleanup.database.touch()
    assert not cleanup.step(deadline=time.monotonic() - 1)
    store.connect.assert_not_called()


def test_read_pin_protects_generation_until_remote_cleanup_confirms_release(graph_paths, event, inventory_database):
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event())
        artifact = artifacts.write("ir", {"nodes": [], "edges": []})
        unit = artifacts.manifest.unit(capture["id"], "fixture", artifact=artifact, discovery="complete", flow="partial")
        artifacts.manifest.fact(unit, capture["id"], "field", {"id": "old", "url": capture["data"]["url"]})
        old = artifacts.manifest.generation(unit)
        pipeline = InventoryPipeline(artifacts, inventory_database)
        drain(pipeline)
        GraphQuery(inventory_database, artifacts=artifacts)
        pin = artifacts.manifest.watermark()
        artifacts.manifest.build_key = "replacement"
        artifacts.manifest.unit(capture["id"], "fixture", artifact=artifact, discovery="complete", flow="complete")
        artifacts.manifest.fact(unit, capture["id"], "field", {"id": "new", "url": capture["data"]["url"]})
        drain(pipeline)
        cleanup = InventoryCleanup(inventory_database, artifacts.root / "artifacts.sqlite")
        with inventory_database.connect().session() as session:
            session.run("MATCH (g:GraphInventoryGeneration {id:$id}) SET g.retired_at=0", id=old).consume()
        assert not cleanup.step()
        assert artifacts.manifest.page("example.com", kind="field", watermark=pin)[0][0]["id"] == "old"
        assert artifacts.connection.execute(
            "SELECT count(*) FROM graph_inventory_outbox WHERE generation=?", (old,)
        ).fetchone()[0] > 0
        with inventory_database.connect().session() as session:
            session.run("MATCH (p:GraphInventoryReadPin {id:$id}) SET p.expires=0", id=pin["pin"]).consume()
        for _ in range(20):
            cleanup.step()
            if artifacts.connection.execute(
                "SELECT state FROM graph_inventory_generations WHERE id=?", (old,)
            ).fetchone() == ("cleaned",):
                break
        else:
            pytest.fail("Retired inventory did not finish bounded cleanup")
        assert artifacts.connection.execute(
            "SELECT count(*) FROM graph_inventory_outbox WHERE generation=?", (old,)
        ).fetchone() == (0,)
        assert artifacts.connection.execute(
            "SELECT artifact FROM graph_inventory_generations WHERE id=?", (old,)
        ).fetchone() == (None,)
        with pytest.raises(ValueError, match="expired"):
            artifacts.manifest.page("example.com", watermark=pin)
        assert artifacts.manifest.page("example.com", kind="field")[0][0]["id"] == "new"
        assert not cleanup.step()
    finally:
        artifacts.close()


@pytest.mark.parametrize("candidate_count", [0, 1, 100])
def test_candidate_paging_rechecks_under_short_explicit_transaction(tmp_path, monkeypatch, candidate_count):
    import sqlite3

    from shyhurricane.graph import inventory_cleanup

    path = tmp_path / "artifacts.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE graph_inventory_generations (id TEXT,state TEXT)")
    monkeypatch.setattr(inventory_cleanup.time, "monotonic", lambda: 0)
    store = MagicMock()
    session = store.connect.return_value.session.return_value.__enter__.return_value
    candidates = [{"id": str(index).zfill(3)} for index in range(candidate_count)]
    session.run.side_effect = [MagicMock(), candidates] + ([[]] if not candidates else [])
    tx = session.begin_transaction.return_value.__enter__.return_value
    tx.run.return_value.single.return_value = None
    cleanup = InventoryCleanup(store, path)
    assert not cleanup.step(deadline=2)
    assert cleanup.candidate_after == ("099" if candidate_count == 100 else "")
    assert session.begin_transaction.call_count == candidate_count
    for call in session.begin_transaction.call_args_list:
        assert call.kwargs["timeout"] == 0.25
    session.execute_write.assert_not_called()
    assert tx.commit.call_count == candidate_count
