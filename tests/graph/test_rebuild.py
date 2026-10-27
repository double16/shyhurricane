"""Offline, resumable rebuild scheduling and durable policy selection."""

import json
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import epochs, policy, rebuild
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.epochs import Epochs
from shyhurricane.graph.policy import ANALYZER_VERSION
from shyhurricane.persistent_queue import get_persistent_queue


@pytest.fixture(autouse=True)
def rebuild_paths(graph_paths, monkeypatch):
    monkeypatch.setattr(rebuild, "persistent_queue_path", lambda db, name: graph_paths / name)


def test_rebuild_dry_run_does_not_create_state_and_validates_scope(graph_paths, event):
    assert rebuild.rebuild("db", dry_run=True)["selected"] == 0
    assert not list(graph_paths.iterdir())
    with pytest.raises(ValueError):
        rebuild.rebuild("db", mode="invalid")
    with pytest.raises(ValueError):
        rebuild.rebuild("db", target="ftp://example.com")
    artifacts = ArtifactStore("db")
    artifacts.register(event())
    artifacts.register(event(url="https://other.test/"))
    artifacts.close()
    assert rebuild.rebuild("db", target="example.com", dry_run=True)["selected"] == 1
    assert not (graph_paths / "graph_queue").exists()
    assert rebuild.rebuild("db", dry_run=True)["queued"] == 0


def test_rebuild_resumes_skips_completed_and_reschedules_failures_or_policy_changes(event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    assert rebuild.rebuild("db")["queued"] == 1
    assert rebuild.rebuild("db")["skipped"] == 1
    queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    item = queue.get(block=False)
    assert item["id"] == capture["id"] and item["rebuild_token"]
    assert rebuild.rebuild("db")["skipped"] == 1
    # An explicit failed-queue retry reuses this durable input token.
    queue.ack(item)
    assert rebuild.rebuild("db")["skipped"] == 1
    with artifacts.connection:
        artifacts.connection.execute(
            "UPDATE analysis_policies SET completed_version=?,completed_mode='summary'", (ANALYZER_VERSION,)
        )
    assert rebuild.rebuild("db")["skipped"] == 1
    assert rebuild.rebuild("db", mode="full")["queued"] == 1
    queue.close()
    artifacts.close()


@pytest.mark.parametrize("failure", [False, True])
def test_worker_uses_durable_policy_and_only_marks_successful_publications(event, monkeypatch, failure):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    with artifacts.connection:
        artifacts.connection.execute(
            "INSERT INTO analysis_policies(capture_id,mode) VALUES (?, 'full')", (capture["id"],)
        )
    store = MagicMock()
    store.read.return_value = []
    graphs = []

    def publish(self, graph):
        graphs.append(graph)
        if failure:
            raise ValueError("publication failed")
        return True

    monkeypatch.setattr(epochs.GraphPublisher, "publish", publish)
    monkeypatch.setattr(epochs.LinkPublisher, "publish", lambda *args: True)
    engine = Epochs(artifacts, store)
    engine.accept(capture, 1)
    for _ in range(30):
        if not engine.available():
            break
        engine.step()
    graph = graphs[0]
    engine.close()
    assert graph.library_analysis == "full"
    completed = artifacts.connection.execute(
        "SELECT completed_version,completed_mode FROM analysis_policies"
    ).fetchone()
    assert completed == ((None, None) if failure else (ANALYZER_VERSION, "full"))
    artifacts.close()


def test_policy_modes_and_cli(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GRAPH_LIBRARY_ANALYSIS", "full")
    assert policy.library_analysis() == "full"
    assert policy.library_analysis("summary") == "summary"
    with pytest.raises(ValueError, match="summary or full"):
        policy.library_analysis("invalid")
    monkeypatch.setattr("sys.argv", ["rebuild", "--data-dir", str(tmp_path), "--target", "example.com", "--dry-run"])
    rebuild.main()
    assert json.loads(capsys.readouterr().out)["dry_run"]


def test_previous_analyzer_policy_is_eligible_for_explicit_rebuild(event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    with artifacts.connection:
        artifacts.connection.execute(
            "INSERT INTO analysis_policies(capture_id,mode,completed_version,completed_mode) "
            "VALUES (?, 'summary', ?, 'summary')", (capture["id"], ANALYZER_VERSION - 1)
        )
    assert rebuild.rebuild("db", dry_run=True)["selected"] == 1
    assert artifacts.connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='reanalysis'"
    ).fetchone() is None
    assert rebuild.rebuild("db")["queued"] == 1
    assert rebuild.rebuild("db")["skipped"] == 1
    artifacts.close()


def test_rebuild_outbox_recovers_delivery_failure_and_redelivers_failed_epoch(event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    queue = MagicMock()
    monkeypatch.setattr(rebuild, "get_persistent_queue", lambda *a, **kw: queue)
    queue.put.side_effect = OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
        rebuild.rebuild("db", mode="full")
    assert artifacts.connection.execute("SELECT delivered FROM graph_rebuild_outbox").fetchone()[0] == 0
    queue.put.side_effect = None
    rebuild.flush_rebuild_requests(artifacts, queue)
    item = queue.put.call_args.args[0]
    token = item["rebuild_token"]
    store = MagicMock()
    store.read.return_value = []
    monkeypatch.setattr(epochs.GraphPublisher, "publish", MagicMock(side_effect=ValueError("bad publication")))
    engine = Epochs(artifacts, store)
    engine.accept(item, 1)
    while engine.available():
        engine.step()
    assert artifacts.connection.execute("SELECT state FROM graph_epoch_inputs").fetchone()[0] == "failed"
    assert rebuild.rebuild("db", mode="full")["queued"] == 1
    assert queue.put.call_args.args[0]["rebuild_token"] == token
    monkeypatch.setattr(epochs.GraphPublisher, "publish", lambda *a: True)
    monkeypatch.setattr(epochs.LinkPublisher, "publish", lambda *a: True)
    engine.accept(queue.put.call_args.args[0], 2)
    while engine.available():
        engine.step()
    assert artifacts.counts() == {"complete": 1}
    assert artifacts.connection.execute("SELECT count(*) FROM graph_epochs").fetchone()[0] == 2
    assert artifacts.connection.execute("SELECT mode FROM analysis_policies WHERE capture_id=?",
                                        (capture["id"],)).fetchone()[0] == "full"
    engine.close()
    artifacts.close()
