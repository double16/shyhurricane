"""Offline, resumable rebuild scheduling and durable policy selection."""

import hashlib
import json
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import policy, rebuild, worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.policy import ANALYZER_VERSION
from shyhurricane.graph.scheduling import ReanalysisScheduler
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
    scheduler = ReanalysisScheduler(artifacts, queue)
    assert scheduler.claim(item)["id"] == capture["id"]
    assert rebuild.rebuild("db")["skipped"] == 1
    scheduler.finish(item)  # A failed analysis never records successful policy completion.
    queue.ack(item)
    assert rebuild.rebuild("db")["queued"] == 1
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
    if failure:
        store.publish.side_effect = ValueError("publication failed")
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *args, **kwargs: iter([capture]))
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "bolt://test", MagicMock(), MagicMock(), False)
    graph = store.publish.call_args.args[0]
    assert graph.library_analysis == "full"
    completed = artifacts.connection.execute(
        "SELECT completed_version,completed_mode FROM analysis_policies"
    ).fetchone()
    assert completed == ((None, None) if failure else (ANALYZER_VERSION, "full"))
    artifacts.close()


def test_policy_recognition_and_cli(monkeypatch, capsys):
    monkeypatch.setenv("GRAPH_LIBRARY_ANALYSIS", "full")
    assert policy.library_analysis() == "full"
    assert policy.library_analysis("summary") == "summary"
    assert policy.recognized_library("unknown mixed application") is None
    source = "verified standalone"
    monkeypatch.setitem(policy.LIBRARIES, hashlib.sha256(source.encode()).hexdigest(), "Fixture")
    assert policy.recognized_library(source) == "Fixture"
    monkeypatch.setattr("sys.argv", ["rebuild", "--database", "db", "--target", "example.com", "--dry-run"])
    rebuild.main()
    assert json.loads(capsys.readouterr().out)["dry_run"]
