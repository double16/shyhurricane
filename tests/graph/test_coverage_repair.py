"""Root-unit identity and conservative background repair regressions."""

import sqlite3
import threading
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.coverage_repair import CoverageRepair
from shyhurricane.graph.extract import extract
from shyhurricane.graph.model import Projection, capture_unit_path, identity
from shyhurricane.graph.policy import ANALYZER_VERSION


@pytest.fixture
def repair(graph_paths, monkeypatch):
    monkeypatch.setattr("shyhurricane.graph.coverage_repair.persistent_queue_path", lambda db, name: graph_paths / name)
    return CoverageRepair("db")


def legacy(artifacts, event, *, flow="complete", artifact=True):
    capture = artifacts.register(event(url="https://example.com"))
    projection = Projection(capture)
    path = artifacts.write("projection", {"fixture": True}) if artifact else None
    key = artifacts.manifest.unit(capture["id"], "capture:" + projection.url,
                                  discovery="complete", flow=flow, artifact=path.name if path else None)
    return capture, key


@pytest.mark.parametrize("url", ["https://example.com", "https://EXAMPLE.com:443", "https://example.com/"])
def test_root_completion_uses_retained_capture_identity(graph_paths, event, url):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url=url))
    extract(capture, artifacts)
    rows = artifacts.connection.execute(
        "SELECT source_path,discovery,flow FROM graph_manifest_units WHERE source_path LIKE 'capture:%'"
    ).fetchall()
    assert rows == [(capture_unit_path(capture), "complete", "complete")]
    assert artifacts.manifest.coverage(scope="example.com")["discovery"] == "complete"
    artifacts.close()


@pytest.mark.parametrize("flow", ["complete", "partial"])
def test_repair_copies_proven_status_and_preserves_ids(repair, event, flow):
    artifacts = ArtifactStore("db")
    capture, _ = legacy(artifacts, event, flow=flow)
    ids = artifacts.connection.execute("SELECT id FROM graph_manifest_units ORDER BY id").fetchall()
    repair.tick(threading.Event())
    repair.tick(threading.Event())
    assert artifacts.connection.execute("SELECT id FROM graph_manifest_units ORDER BY id").fetchall() == ids
    assert artifacts.manifest.coverage(scope="example.com") == {"discovery": "complete", "flow": flow, "units": 2}
    root = identity("analysis-unit-v2", ANALYZER_VERSION, capture["id"], capture_unit_path(capture))
    assert artifacts.connection.execute("SELECT artifact FROM graph_manifest_units WHERE id=?", (root,)).fetchone()[0]
    artifacts.close()


@pytest.mark.parametrize("case", ["missing_archive", "missing_file", "failed", "blocked", "version", "capture"])
def test_repair_requires_matching_completed_archive(repair, event, case):
    artifacts = ArtifactStore("db")
    capture, key = legacy(artifacts, event, artifact=case != "missing_archive")
    with artifacts.connection:
        if case == "missing_file":
            reference = artifacts.connection.execute(
                "SELECT artifact FROM graph_manifest_units WHERE id=?", (key,)
            ).fetchone()[0]
            artifacts.resolve(reference).unlink()
        elif case in {"failed", "blocked"}:
            artifacts.connection.execute("UPDATE graph_manifest_units SET flow=? WHERE id=?", (case, key))
        elif case == "version":
            artifacts.connection.execute("UPDATE graph_manifest_units SET id=? WHERE id=?", ("old-version", key))
        elif case == "capture":
            artifacts.connection.execute("UPDATE graph_manifest_units SET capture_id='other' WHERE id=?", (key,))
    repair.tick(threading.Event())
    assert artifacts.connection.execute(
        "SELECT discovery,flow FROM graph_manifest_units WHERE source_path=?", (capture_unit_path(capture),)
    ).fetchone() == ("pending", "pending")
    artifacts.close()


def test_repair_bounds_batches_and_resumes(repair, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    for index in range(220):
        artifacts.manifest.unit(capture["id"], f"deferred:{index}")
    stop = threading.Event()
    repair.tick(stop)
    first = repair.after
    repair.tick(stop)
    assert repair.after > first
    repair.tick(stop)
    assert repair.after == ""
    stop.set()
    repair.tick(stop)
    assert repair.after == ""
    artifacts.close()


def test_repair_handles_missing_database_and_lock_contention(repair, event):
    repair.tick(threading.Event())
    artifacts = ArtifactStore("db")
    legacy(artifacts, event)
    with sqlite3.connect(artifacts.root / "artifacts.sqlite") as writer:
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            repair.tick(threading.Event())
        writer.rollback()
    repair.tick(threading.Event())
    assert artifacts.manifest.coverage(scope="example.com")["discovery"] == "complete"
    artifacts.close()


def test_repair_stops_at_deadline(repair, event, monkeypatch):
    artifacts = ArtifactStore("db")
    legacy(artifacts, event)
    clock = MagicMock(side_effect=[0, 2, 2, 2])
    monkeypatch.setattr("shyhurricane.graph.coverage_repair.time.monotonic", clock)
    repair.tick(threading.Event())
    assert repair.after == ""
    artifacts.close()


@pytest.mark.parametrize("blank", [None, "", " \t\n"])
def test_inventory_optional_blank_filters_match_omission(graph_paths, event, blank):
    from shyhurricane.graph.manifest_query import manifest_query
    from shyhurricane.graph.query import GraphQuery

    artifacts = ArtifactStore("db")
    artifacts.register(event())
    query = GraphQuery(MagicMock(), artifacts=artifacts)
    expected = query.endpoints("example.com")["results"]
    assert expected
    assert query.endpoints("example.com", url=blank, method=blank)["results"] == expected
    assert manifest_query(artifacts, "example.com", kind="resource", url=blank,
                          context_url=blank, method=blank)["results"] == expected
    assert query.endpoints("example.com", url="https://example.com/missing")["results"] == []
    assert query.endpoints("example.com", method="POST")["results"] == []
    artifacts.close()


@pytest.mark.parametrize("discovery,flow", [("failed", "pending"), ("pending", "blocked"), ("complete", "pending")])
def test_repair_does_not_overwrite_nonpending_root_state(repair, event, discovery, flow):
    artifacts = ArtifactStore("db")
    capture, _ = legacy(artifacts, event)
    with artifacts.connection:
        artifacts.connection.execute(
            "UPDATE graph_manifest_units SET discovery=?,flow=? WHERE source_path=?",
            (discovery, flow, capture_unit_path(capture)),
        )
    repair.tick(threading.Event())
    assert artifacts.connection.execute(
        "SELECT discovery,flow FROM graph_manifest_units WHERE source_path=?", (capture_unit_path(capture),)
    ).fetchone() == (discovery, flow)
    artifacts.close()


@pytest.mark.parametrize("reference", ["../outside.json", "missing.json"])
def test_repair_ignores_invalid_archive_references(repair, reference):
    assert not repair.archive_exists(reference)


def test_repair_cancellation_before_update_rolls_back(repair, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture, _ = legacy(artifacts, event)
    stop = threading.Event()

    def exists(reference):
        stop.set()
        return True

    monkeypatch.setattr(repair, "archive_exists", exists)
    repair.tick(stop)
    assert artifacts.connection.execute(
        "SELECT discovery FROM graph_manifest_units WHERE source_path=?", (capture_unit_path(capture),)
    ).fetchone()[0] == "pending"
    artifacts.close()
