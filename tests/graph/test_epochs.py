"""Finite dense reconciliation, frozen inputs, phase barriers, and durable recovery."""

import sqlite3
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import ServiceUnavailable

from shyhurricane.graph import epochs, worker
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.epochs import EPOCH_VERSION, Epochs, epoch_status
from shyhurricane.graph.model import identity, projection_snapshot
from shyhurricane.graph.publication import PublicationConflict
from shyhurricane.persistent_queue import get_persistent_queue


@pytest.fixture
def runtime(graph_paths, monkeypatch):
    artifacts = ArtifactStore("db")
    store = MagicMock()
    store.read.return_value = []
    writes = {"structural": [], "links": []}
    published = {}

    def publish(kind, projection):
        digest = identity(projection_snapshot(projection))
        key = (kind, projection.event["id"])
        if published.get(key) == digest:
            return False
        published[key] = digest
        writes[kind].append(projection.event["id"])
        return True

    monkeypatch.setattr(epochs.GraphPublisher, "publish", lambda self, p: publish("structural", p))
    monkeypatch.setattr(epochs.LinkPublisher, "publish", lambda self, p: publish("links", p))
    engine = Epochs(artifacts, store)
    yield engine, artifacts, store, writes
    engine.close()
    artifacts.close()


def drain(engine, maximum=50000):
    for _ in range(maximum):
        if not engine.available():
            break
        engine.step()
    else:
        pytest.fail("Epoch did not drain within its deterministic work bound")
    return epoch_status(engine.connection)


def test_independent_streaming_captures_do_linear_work_and_compact_jobs(runtime, event):
    engine, artifacts, _, writes = runtime
    for index in range(24):
        capture = artifacts.register(event(url=f"https://example.com/{index}"))
        engine.accept(capture, index + 1)
        assert drain(engine)["phase"] == "done"
    assert len(writes["structural"]) == len(writes["links"]) == 24
    assert artifacts.connection.execute("SELECT sum(affected) FROM graph_epochs").fetchone()[0] == 24
    assert artifacts.connection.execute("SELECT count(*) FROM graph_epoch_jobs").fetchone()[0] == 1


def test_failed_dependency_blocks_only_its_consumers(runtime, event):
    engine, artifacts, _, _ = runtime
    bad = artifacts.register(event(url="https://example.com/bad.js"))
    consumer = artifacts.register(event(url="https://example.com/consumer"))
    independent = artifacts.register(event(url="https://example.com/independent"))
    artifacts.manifest.dependency(consumer["id"], bad["data"]["url"], "LOADS")
    for index, capture in enumerate([bad, consumer, independent]):
        engine.accept(capture, index + 1)
    engine.start()
    epoch = epoch_status(engine.connection)["id"]
    with engine.connection:
        engine.quarantine(epoch, (bad["id"], "references", ""), ValueError("invalid"))
    status = drain(engine)
    assert status["phase"] == "done"
    assert status["stages"] == {"failed": 1, "blocked": 1, "done": 1}
    queue = MagicMock()
    engine.settle(queue)
    assert queue.ack_failed.call_count == 2 and queue.ack.call_count == 1


def test_dense_cycles_drain_with_one_publication_per_phase_and_no_replay(runtime, event):
    engine, artifacts, _, writes = runtime
    count = 25
    events = [event(url=f"https://example.com/{i}", body="".join(
        f'<a href="/{j}">link</a>' for j in range(count)
    )) for i in range(count)]
    for capture in events:
        artifacts.register(capture)
    for index, capture in enumerate(events):
        engine.accept(capture, index + 1)
    status = drain(engine)
    assert status["phase"] == "done" and status["affected"] == status["completed"] == count
    assert len(writes["structural"]) == len(writes["links"]) == count
    for index, capture in enumerate(events):
        engine.accept(capture, 100 + index)
    for _ in range(10):
        engine.step()
    assert len(writes["structural"]) == len(writes["links"]) == count
    assert artifacts.connection.execute("SELECT count(*) FROM graph_epochs").fetchone()[0] == 1
    queue = MagicMock()
    engine.settle(queue)
    assert queue.ack.call_count == count * 2
    assert not engine.available()


def test_snapshot_freezes_captures_policies_and_finishes_before_next_epoch(runtime, event):
    engine, artifacts, _, writes = runtime
    first = artifacts.register(event(body="first"))
    engine.accept(first, 1)
    engine.step()
    first_id = epoch_status(engine.connection)["id"]
    later = artifacts.register(event(body="later"))
    with artifacts.connection:
        artifacts.connection.execute("INSERT INTO analysis_policies(capture_id,mode) VALUES (?,'full')", (first["id"],))
    engine.accept(later, 2)
    frozen = engine.snapshot
    assert frozen.latest(first["data"]["url"])["id"] == first["id"]
    assert frozen.connection.execute("SELECT count(*) FROM captures").fetchone()[0] == 1
    assert frozen.connection.execute("SELECT mode FROM analysis_policies").fetchone()[0] == "summary"
    while epoch_status(engine.connection)["id"] == first_id and engine.available():
        engine.step()
        row = engine.connection.execute("SELECT phase FROM graph_epochs WHERE id=?", (first_id,)).fetchone()
        if row[0] == "done":
            assert later["id"] not in writes["structural"]
            break
    assert drain(engine)["phase"] == "done"
    assert engine.connection.execute("SELECT count(*) FROM graph_epochs").fetchone()[0] == 2
    assert later["id"] in writes["structural"]


def test_restart_at_every_slice_keeps_work_and_phase_barrier(runtime, event):
    engine, artifacts, store, writes = runtime
    for i in range(3):
        capture = artifacts.register(event(url=f"https://example.com/{i}"))
        engine.accept(capture, i)
    for _ in range(100):
        if not engine.available():
            break
        engine.step()
        status = epoch_status(engine.connection)
        if status["phase"] != "links" and status["phase"] != "done":
            assert not writes["links"]
        engine.close()
        engine = Epochs(artifacts, store)
    assert epoch_status(engine.connection)["phase"] == "done"
    assert len(writes["structural"]) == len(writes["links"]) == 3
    engine.close()


@pytest.mark.parametrize("failure", [ValueError("bad"), PublicationConflict("dependency changed")])
def test_failure_is_visible_and_requires_explicit_queue_redelivery(runtime, event, monkeypatch, failure):
    engine, artifacts, _, _ = runtime
    capture = artifacts.register(event())
    engine.accept(capture, 1)
    original = epochs.GraphPublisher.publish
    monkeypatch.setattr(epochs.GraphPublisher, "publish", MagicMock(side_effect=failure))
    status = drain(engine)
    assert status["phase"] == "done" and status["stages"]["failed"] == 1
    assert status["conflicts"] == int(isinstance(failure, PublicationConflict))
    assert artifacts.counts() == {"failed": 1}
    queue = MagicMock()
    engine.settle(queue)
    queue.ack_failed.assert_called_once_with(id=1)
    assert not engine.available()
    monkeypatch.setattr(epochs.GraphPublisher, "publish", original)
    engine.accept(capture, 1)
    assert drain(engine)["phase"] == "done"
    engine.settle(queue)
    queue.ack.assert_called_once_with(id=1)


def test_transient_retry_preserves_checkpoint_and_uses_backoff(runtime, event, monkeypatch):
    engine, artifacts, _, _ = runtime
    capture = artifacts.register(event())
    engine.accept(capture, 1)
    original = epochs.GraphPublisher.publish
    monkeypatch.setattr(epochs.GraphPublisher, "publish", MagicMock(side_effect=ServiceUnavailable("offline")))
    status = drain(engine)
    assert status["retries"] == 1 and status["phase"] == "structural"
    assert status["next_attempt"] > epochs.time.time()
    monkeypatch.setattr(epochs.GraphPublisher, "publish", original)
    with engine.connection:
        engine.connection.execute("UPDATE graph_epochs SET next_attempt=0")
    assert drain(engine)["phase"] == "done"


def test_legacy_work_and_unknown_checkpoint_versions_fail_before_publication(graph_paths):
    artifacts = ArtifactStore("db")
    with artifacts.connection:
        artifacts.connection.execute("CREATE TABLE reanalysis(state TEXT)")
        artifacts.connection.execute("INSERT INTO reanalysis VALUES ('running')")
    with pytest.raises(ValueError, match="fresh graph state"):
        Epochs(artifacts, MagicMock())
    artifacts.connection.execute("DELETE FROM reanalysis")
    engine = Epochs(artifacts, MagicMock())
    with artifacts.connection:
        artifacts.connection.execute(
            "INSERT INTO graph_epochs(version,phase,snapshot,created_at) VALUES (?,'references','missing',0)",
            (EPOCH_VERSION + 1,),
        )
    with pytest.raises(ValueError, match="Unsupported"):
        Epochs(artifacts, MagicMock())
    engine.close()
    artifacts.close()


def test_empty_status_legacy_delivery_and_corrupt_checkpoint(runtime, event):
    engine, artifacts, _, _ = runtime
    assert epoch_status(engine.connection) is None
    capture = artifacts.register(event())
    with pytest.raises(ValueError, match="Legacy"):
        engine.accept({**capture, "reanalysis_ticket": "old"}, 1)
    engine.accept(capture, 2)
    engine.step()
    reference = engine.connection.execute("SELECT checkpoint FROM graph_epoch_jobs").fetchone()[0]
    artifacts.connection.execute("UPDATE graph_blobs SET payload=? WHERE digest IN "
                                 "(SELECT digest FROM graph_objects WHERE ref=?)", (b"bad", reference))
    artifacts.connection.commit()
    assert drain(engine)["stages"]["failed"] == 1
    empty = sqlite3.connect(":memory:")
    assert epoch_status(empty) is None
    empty.close()


def test_worker_consumes_raw_receipts_and_closes_resources(graph_paths, event, monkeypatch):
    queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    queue.put(event())
    store = MagicMock()
    health, stop = MagicMock(), MagicMock()
    stop.is_set.return_value = False
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **k: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    receipts = [queue.get(block=False, raw=True)] + [{"graph_epoch": True}] * 20
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *a, **k: iter(receipts))
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)
    monkeypatch.setattr(epochs.GraphPublisher, "publish", lambda *a: True)
    monkeypatch.setattr(epochs.LinkPublisher, "publish", lambda *a: True)
    worker.graph_worker("db", "bolt://localhost", health, stop, False)
    artifacts = ArtifactStore("db")
    assert epoch_status(artifacts.connection)["phase"] == "done"
    assert artifacts.connection.execute("SELECT count(*) FROM graph_epoch_receipts").fetchone()[0] == 0
    artifacts.close()
    store.close.assert_called_once()


@pytest.mark.parametrize("svg", [False, True])
@pytest.mark.parametrize("document_first", [False, True])
def test_late_documents_shared_imports_and_source_maps_preserve_contexts(
    runtime, event, monkeypatch, svg, document_first
):
    from shyhurricane.graph.extract import extract as real_extract

    engine, artifacts, _, _ = runtime
    document = event(
        url="https://example.com/document",
        body='<svg xmlns="http://www.w3.org/2000/svg"><script href="/entry.js"/></svg>' if svg
        else '<script src="/entry.js"></script>',
        mime="image/svg+xml" if svg else "text/html",
    )
    script = event(url="https://example.com/entry.js", body='import "./chunk.js";', mime="text/javascript")
    chunk = event(url="https://example.com/chunk.js", body="fetch('/data')", mime="text/javascript")
    calls = []

    def runner(source, filename):
        calls.append(filename)
        references = [{"url": "./chunk.js", "kind": "IMPORTS"}] if "entry" in filename else [
            {"url": "/data", "kind": "REQUESTS"}
        ]
        return {"nodes": [], "edges": [], "references": references, "gaps": []}

    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: source)
    monkeypatch.setattr(epochs, "extract", lambda *a, **kw: real_extract(*a, javascript_runner=runner, **kw))
    first, second = ([document], [script, chunk]) if document_first else ([script, chunk], [document])
    for capture in first:
        artifacts.register(capture)
        engine.accept(capture, len(calls) + 1)
    assert drain(engine)["phase"] == "done"
    recorded = []
    original = epochs.GraphPublisher.publish

    def record(self, projection):
        recorded.append(projection)
        return original(self, projection)

    monkeypatch.setattr(epochs.GraphPublisher, "publish", record)
    for index, capture in enumerate(second):
        artifacts.register(capture)
        engine.accept(capture, 100 + index)
    assert drain(engine)["phase"] == "done"
    projected = next(item for item in recorded if item.event["id"] == chunk["id"])
    assert [context["id"] for context in projected.contexts] == [document["id"]]
    assert any(node.get("url") == "https://example.com/data" for node in projected.nodes.values())
    assert len(calls) == 2  # Reference and contextual projections share the cached AST.


def test_long_planning_cannot_be_starved_by_new_inputs(runtime, event, monkeypatch):
    engine, artifacts, _, writes = runtime
    first = artifacts.register(event())
    engine.accept(first, 1)
    slices = []

    class Planner:
        def __init__(self, store, projection):
            self.index = 0

        def restore(self, state):
            self.index = state["index"]

        def checkpoint(self):
            return {"index": self.index, "links": {}}

        def plan_slice(self, **kwargs):
            self.index += 1
            slices.append(self.index)
            if self.index == 1:
                later = artifacts.register(event(url="https://example.com/later"))
                engine.accept(later, 2)
            assert len(writes["structural"]) == 1
            return self.index >= 5

    monkeypatch.setattr(epochs, "LinkPlanner", Planner)
    while not writes["links"]:
        engine.step()
    assert slices == [1, 2, 3, 4, 5]
    assert len(writes["structural"]) == 1
    assert epoch_status(engine.connection)["waiting_inputs"] == 1


def test_site_sized_capture_history_drains_and_stays_idle(runtime, event):
    engine, artifacts, _, writes = runtime
    for i in range(400):
        capture = artifacts.register(event(url=f"https://example.com/{i % 80}", body=str(i)))
        engine.accept(capture, i)
    assert drain(engine)["completed"] == 400
    assert len(writes["structural"]) == len(writes["links"]) == 400
    before = epoch_status(engine.connection)
    for _ in range(120):
        engine.step()
    assert epoch_status(engine.connection) == before


def test_worker_health_race_rejects_legacy_and_preserves_unclaimed_work(graph_paths, event, monkeypatch):
    queue = MagicMock()
    healthy, stopped = MagicMock(), MagicMock()
    stopped.is_set.return_value = False
    healthy.is_set.side_effect = [False, True, True, False]
    store = MagicMock()
    bad = {"pqid": 2, "data": {**event(), "reanalysis_ticket": "legacy"}}
    unclaimed = {"pqid": 1, "data": event()}
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **k: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)

    def deliveries(*args, **kwargs):
        assert kwargs["idle_callback"]() is None
        yield unclaimed
        yield bad
        yield {"graph_epoch": True}

    monkeypatch.setattr(worker, "persistent_queue_get", deliveries)
    worker.graph_worker("db", "graph", healthy, stopped, False)
    queue.nack.assert_called_once_with(unclaimed)
    queue.ack_failed.assert_called_once_with(bad)
    store.close.assert_called_once()


def test_worker_initialization_failure_closes_without_reclaiming_legacy_queue(graph_paths, monkeypatch, caplog):
    queue, store = MagicMock(), MagicMock()
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **k: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *a: store)
    monkeypatch.setattr(worker, "Epochs", MagicMock(side_effect=ValueError("legacy work")))
    with pytest.raises(ValueError, match="legacy work"):
        worker.graph_worker("db", "graph", MagicMock(), MagicMock(), False)
    assert "durable graph work retained" in caplog.text
    queue.resume_unack_tasks.assert_not_called()
    store.close.assert_called_once()
    queue.close.assert_called_once()


def test_fetched_source_map_is_pinned_and_replayed_from_reference_cache(runtime, event, monkeypatch):
    import json

    from shyhurricane.graph.extract import extract as real_extract

    engine, artifacts, _, _ = runtime
    engine.open_world = True
    source_map = json.dumps({"version": 3, "sources": ["src/original.js"],
                             "sourcesContent": ["const original=1;"]})
    fetches = []
    analyses = []

    def fetch(self, url, source, headers, open_world, **kwargs):
        fetches.append(open_world)
        return source_map

    def runner(source, filename):
        analyses.append(filename)
        return {"nodes": [], "edges": [], "references": [], "gaps": []}

    monkeypatch.setattr(ArtifactStore, "source_map", fetch)
    monkeypatch.setattr(epochs, "extract", lambda *a, **kw: real_extract(*a, javascript_runner=runner, **kw))
    script = artifacts.register(event(url="https://example.com/app.js", mime="text/javascript", body="delivered();"))
    engine.accept(script, 1)
    assert drain(engine)["phase"] == "done"
    document = artifacts.register(event(body='<script src="/app.js"></script>'))
    engine.accept(document, 2)
    assert drain(engine)["phase"] == "done"
    assert fetches == [True]
    assert analyses == ["https://example.com/app.js"]


def test_browser_relative_lazy_dependencies_reach_fixed_point_before_analysis(runtime, event, monkeypatch):
    from shyhurricane.graph.extract import extract as real_extract

    engine, artifacts, _, _ = runtime
    page = event(url="https://example.com/dir/page", body='<script src="/loader.js"></script>')
    loader = event(url="https://example.com/loader.js", body="load('chunk.js')", mime="text/javascript")
    chunk = event(url="https://example.com/dir/chunk.js", body="fetch('result')", mime="text/javascript")
    analyses = []

    def runner(source, filename):
        analyses.append(filename)
        reference = {"url": "chunk.js", "kind": "LOADS"} if filename.endswith("loader.js") else {
            "url": "result", "kind": "REQUESTS"
        }
        return {"nodes": [], "edges": [], "references": [reference], "gaps": []}

    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: source)
    monkeypatch.setattr(epochs, "extract", lambda *a, **kw: real_extract(*a, javascript_runner=runner, **kw))
    projections = []
    original = epochs.GraphPublisher.publish

    def record(self, projection):
        projections.append(projection)
        return original(self, projection)

    monkeypatch.setattr(epochs.GraphPublisher, "publish", record)
    for index, capture in enumerate([chunk, loader, page]):
        artifacts.register(capture)
        engine.accept(capture, index)
    assert drain(engine)["phase"] == "done"
    final = next(item for item in projections if item.event["id"] == chunk["id"])
    assert [context["id"] for context in final.contexts] == [page["id"]]
    assert any(node.get("url") == "https://example.com/dir/result" for node in final.nodes.values())
    assert len(analyses) == 2
    assert len(projections) == 3


def test_explicit_rebuild_policy_does_not_fetch_source_maps(runtime, event, monkeypatch):
    from shyhurricane.graph.extract import extract as real_extract

    engine, artifacts, _, _ = runtime
    engine.open_world = True
    capture = artifacts.register(event(url="https://example.com/app.js", body="source", mime="text/javascript"))
    with artifacts.connection:
        artifacts.connection.execute(
            "INSERT INTO analysis_policies(capture_id,mode) VALUES (?,'full')", (capture["id"],)
        )
    requests = []

    def source_map(self, url, source, headers, open_world, **kwargs):
        requests.append(open_world)
        return None

    monkeypatch.setattr(ArtifactStore, "source_map", source_map)
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.deobfuscate_javascript", lambda source: source)
    monkeypatch.setattr(epochs, "extract", lambda *a, **kw: real_extract(
        *a, javascript_runner=lambda *a: {"nodes": [], "edges": [], "references": [], "gaps": []}, **kw,
    ))
    engine.accept(capture, 1)
    assert drain(engine)["phase"] == "done"
    assert requests == [False]


def test_retry_uses_frozen_policy_when_a_new_policy_request_is_waiting(runtime, event, monkeypatch):
    engine, artifacts, _, _ = runtime
    capture = artifacts.register(event())
    engine.accept(capture, 1)
    original = epochs.GraphPublisher.publish
    monkeypatch.setattr(epochs.GraphPublisher, "publish", MagicMock(side_effect=ValueError("failed")))
    assert drain(engine)["stages"]["failed"] == 1
    with artifacts.connection:
        artifacts.connection.execute(
            "INSERT INTO analysis_policies(capture_id,mode) VALUES (?,'full')", (capture["id"],)
        )
    engine.accept({**capture, "rebuild_token": "next-policy"}, 2)
    assert engine.available()
    monkeypatch.setattr(epochs.GraphPublisher, "publish", original)
    engine.accept(capture, 1)
    assert drain(engine)["phase"] == "done"
    assert artifacts.connection.execute("SELECT count(*) FROM graph_epochs").fetchone()[0] == 3
    assert artifacts.connection.execute(
        "SELECT completed_mode FROM analysis_policies WHERE capture_id=?", (capture["id"],)
    ).fetchone()[0] == "full"
    assert artifacts.connection.execute(
        "SELECT count(*) FROM graph_epoch_inputs WHERE state='waiting'"
    ).fetchone()[0] == 0


def test_activity_observes_job_and_recovers_interrupted_metadata(runtime, event, monkeypatch):
    engine, artifacts, store, _ = runtime
    engine.accept(event(), 1)
    engine.start()
    original = engine.run_job
    observed = []

    def run(*args):
        observed.append(epoch_status(engine.connection)["current_job"])
        return original(*args)

    monkeypatch.setattr(engine, "run_job", run)
    engine.step()
    status = epoch_status(engine.connection)
    assert observed[0]["stage"] == "references"
    assert observed[0]["started_at"] > 0
    assert not observed[0]["interrupted"]
    assert status["current_job"] is None
    assert status["last_progress_at"] > 0
    assert status["discovery_completed"] == status["discovery_total"] == 1
    with engine.connection:
        engine.connection.execute("UPDATE graph_epoch_activity SET capture_id='interrupted',stage='references'")
    restarted = Epochs(artifacts, store)
    assert epoch_status(engine.connection)["current_job"]["interrupted"]
    restarted.close()
    assert drain(engine)["current_job"] is None


def test_failed_job_clears_activity_without_success_timestamp(runtime, event, monkeypatch):
    engine, _, _, _ = runtime
    engine.accept(event(), 1)
    monkeypatch.setattr(engine, "run_job", lambda *args: (_ for _ in ()).throw(ValueError("invalid")))
    engine.step()
    status = epoch_status(engine.connection)
    assert status["current_job"] is None
    assert status["last_progress_at"] is None
    assert status["failed"] == 1
    assert status["discovery_completed"] == 0


def test_root_unit_materialization_uses_original_url(runtime, event):
    engine, artifacts, _, _ = runtime
    capture = artifacts.register(event(url="https://example.com"))
    engine.accept(capture, 1)
    assert drain(engine)["phase"] == "done"
    assert artifacts.connection.execute(
        "SELECT discovery,flow,materialization FROM graph_manifest_units WHERE source_path=?",
        ("capture:https://example.com",),
    ).fetchone() == ("complete", "complete", "complete")


@pytest.mark.parametrize("phase,due,expansion,expected", [
    ("references", False, False, False),
    ("references", False, True, False),
    ("references", True, False, True),
    ("references", True, True, True),
    ("failed", False, False, True),
    ("failed", False, True, True),
    ("done", False, False, True),
])
def test_available_matches_runnable_work_with_waiting_inputs(runtime, event, monkeypatch, phase, due, expansion, expected):
    engine, artifacts, _, _ = runtime
    engine.accept(artifacts.register(event(url="https://example.com/first")), 1)
    engine.start()
    engine.accept(artifacts.register(event(url="https://example.com/later")), 2)
    monkeypatch.setattr(epochs.time, "time", lambda: 100)
    monkeypatch.setattr(engine.expansions, "available", lambda: expansion)
    with engine.connection:
        engine.connection.execute(
            "UPDATE graph_epochs SET phase=?,next_attempt=?", (phase, 99 if due else 101),
        )
    assert bool(engine.available()) is expected


@pytest.mark.parametrize("receipt", [{"graph_epoch": True}, {"pqid": 1, "data": {"id": "capture"}}])
def test_worker_shutdown_after_delivery_skips_epoch_step(graph_paths, monkeypatch, receipt):
    queue, engine, stop = MagicMock(), MagicMock(), MagicMock()
    stop.is_set.return_value = False
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *a, **k: queue)
    monkeypatch.setattr(worker, "GraphStore", MagicMock())
    monkeypatch.setattr(worker, "Epochs", lambda *a, **k: engine)
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *a: True)

    def deliveries(*args, **kwargs):
        assert kwargs["prefer_ready_work"] is True
        stop.is_set.return_value = True
        yield receipt

    monkeypatch.setattr(worker, "persistent_queue_get", deliveries)
    worker.graph_worker("db", "graph", MagicMock(), stop, False)
    if "graph_epoch" not in receipt:
        queue.nack.assert_called_once_with(receipt)
    else:
        queue.nack.assert_not_called()
    engine.accept.assert_not_called()
    engine.step.assert_not_called()
    engine.close.assert_called_once()


@pytest.mark.parametrize("restart", [False, True])
def test_phase_failure_allows_independent_work_and_explicit_retry(runtime, event, monkeypatch, restart):
    engine, artifacts, store, writes = runtime
    capture = artifacts.register(event())
    token = engine.accept(capture, 1)
    engine.step()
    failed_epoch = epoch_status(engine.connection)["id"]
    original = engine.expand_membership

    def fail_phase(epoch):
        raise ValueError("phase boundary failed")

    monkeypatch.setattr(engine, "expand_membership", fail_phase)
    engine.step()
    monkeypatch.setattr(engine, "expand_membership", original)
    assert epoch_status(engine.connection)["phase"] == "failed"
    retained = artifacts.connection.execute(
        "SELECT snapshot,error FROM graph_epochs WHERE id=?", (failed_epoch,),
    ).fetchone()
    assert retained[0] and "phase boundary failed" in retained[1]
    queue = MagicMock()
    engine.settle(queue)
    queue.ack_failed.assert_called_once_with(id=1)
    assert not engine.available()
    if restart:
        engine.close()
        engine = Epochs(artifacts, store)
    try:
        independent = artifacts.register(event(url="https://example.com/independent"))
        engine.accept(independent, 2)
        assert drain(engine)["phase"] == "done"
        assert capture["id"] not in writes["structural"]
        assert engine.connection.execute(
            "SELECT state FROM graph_epoch_inputs WHERE token=?", (token,),
        ).fetchone() == ("failed",)
        assert engine.accept(capture, 1) == token
        assert engine.available()
        assert drain(engine)["phase"] == "done"
        engine.settle(queue)
        assert capture["id"] in writes["structural"]
        assert engine.connection.execute(
            "SELECT phase,snapshot,error FROM graph_epochs WHERE id=?", (failed_epoch,),
        ).fetchone() == ("failed", *retained)
        assert artifacts.blobs.exists(retained[0])
        assert engine.connection.execute("SELECT count(*) FROM graph_epochs").fetchone()[0] == 3
        assert queue.ack.call_count == 2
        assert not engine.available()
    finally:
        engine.close()


@pytest.mark.parametrize("explicit", [False, True])
def test_expanded_snapshot_survives_obsolete_snapshot_collection(runtime, event, monkeypatch, explicit):
    from shyhurricane.graph.epoch_catalog import SnapshotArtifacts

    engine, artifacts, _, _ = runtime
    first = artifacts.register(event())
    second = artifacts.register(event(url="https://example.com/dependency"))
    if explicit:
        with artifacts.connection:
            artifacts.connection.execute(
                "INSERT INTO analysis_policies(capture_id,mode) VALUES (?,'full')", (second["id"],),
            )
    engine.accept(first, 1)
    engine.start()
    epoch, previous = engine.connection.execute("SELECT id,snapshot FROM graph_epochs").fetchone()
    old = engine.open_snapshot(epoch, previous)
    artifacts.manifest.dependency(first["id"], second["data"]["url"], "LOADS")
    assert engine.expand_membership(epoch)
    assert engine.snapshot is None
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        old.connection.execute("SELECT 1")
    reference = engine.connection.execute("SELECT snapshot FROM graph_epochs WHERE id=?", (epoch,)).fetchone()[0]
    assert reference != previous
    now = epochs.time.time()
    monkeypatch.setattr(epochs.time, "time", lambda: now + 3601)
    for _ in range(20):
        with artifacts.connection:
            result = artifacts.blobs.maintain(batch=500)
        if not result["pending"]:
            break
    assert not artifacts.blobs.exists(previous)
    reopened = engine.open_snapshot(epoch, reference)
    assert reopened.snapshot_reference == reference
    # A parser subprocess constructs this same snapshot from its request reference.
    child = SnapshotArtifacts(artifacts.root, reopened.snapshot_reference)
    try:
        for snapshot in (reopened, child):
            assert snapshot.connection.execute(
                "SELECT mode FROM analysis_policies WHERE capture_id=?", (second["id"],),
            ).fetchone() == ("full" if explicit else "summary",)
            assert bool(snapshot.connection.execute(
                "SELECT 1 FROM epoch_explicit_policies WHERE capture_id=?", (second["id"],),
            ).fetchone()) is explicit
    finally:
        child.close()
    assert drain(engine)["phase"] == "done"


def test_failed_membership_commit_preserves_jobs_ownership_and_open_snapshot(runtime, event):
    engine, artifacts, _, _ = runtime
    first = artifacts.register(event())
    second = artifacts.register(event(url="https://example.com/dependency"))
    engine.accept(first, 1)
    engine.start()
    epoch, reference = engine.connection.execute("SELECT id,snapshot FROM graph_epochs").fetchone()
    snapshot = engine.open_snapshot(epoch, reference)
    artifacts.manifest.dependency(first["id"], second["data"]["url"], "LOADS")
    nodes = engine.connection.execute("SELECT id,owners FROM graph_nodes ORDER BY id").fetchall()

    def deny_commit(action, argument, *unused):
        committing = action == sqlite3.SQLITE_TRANSACTION and argument == "COMMIT"
        return sqlite3.SQLITE_DENY if committing else sqlite3.SQLITE_OK

    engine.connection.set_authorizer(deny_commit)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            engine.expand_membership(epoch)
    finally:
        engine.connection.set_authorizer(None)
    assert engine.snapshot is snapshot
    assert engine.connection.execute("SELECT snapshot,affected FROM graph_epochs").fetchone() == (reference, 1)
    assert engine.connection.execute("SELECT capture_id FROM graph_epoch_jobs").fetchall() == [(first["id"],)]
    assert engine.connection.execute("SELECT id,owners FROM graph_nodes ORDER BY id").fetchall() == nodes
    assert snapshot.read(reference)["policies"] == [[first["id"], "summary", False]]
    assert snapshot.connection.execute(
        "SELECT mode FROM analysis_policies WHERE capture_id=?", (second["id"],),
    ).fetchone() is None
    assert engine.expand_membership(epoch)
    assert drain(engine)["phase"] == "done"
