"""Durable shared-script work, recovery, fairness, and bounded progress."""

import json
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import Neo4jError

from shyhurricane.graph import continuations, links
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.continuations import Continuations
from shyhurricane.graph.extract import extract
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import Projection
from shyhurricane.graph.publication import PublicationConflict


def timeout():
    return Neo4jError._hydrate_neo4j(
        code="Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration", message="read deadline"
    )


@pytest.fixture
def jobs(graph_paths):
    artifacts = ArtifactStore("db")
    yield Continuations(artifacts)
    artifacts.close()


def script(event):
    return event(url="https://example.com/app.js", body="document.querySelector('#search')", mime="text/javascript")


def test_discovery_pages_all_12538_consumers_without_loading_them_at_once(jobs, event):
    capture = script(event)
    page = event(body='<base href="/base/"><script src="/app.js"></script>')
    path = jobs.artifacts.write("shared-fixture-body", page)
    jobs.connection.executemany("INSERT INTO captures VALUES (?,?,?,?)", [
        (f"page-{index:05}", page["data"]["url"], index, str(path)) for index in range(12538)
    ])
    jobs.connection.executemany("INSERT INTO refs VALUES (?,?)", [
        (capture["data"]["url"], f"page-{index:05}") for index in range(12538)
    ])
    jobs.connection.commit()
    key = jobs.enqueue(capture, capture, False)
    assert jobs.enqueue(capture, capture, False) == key
    state = jobs.load(key)
    slices = 0
    while state["stage"] == "discovery":
        before = len(state["contexts"])
        jobs.discover(state)
        assert len(state["contexts"]) - before <= 100
        slices += 1
    assert len(state["contexts"]) == 12538 and slices == 126
    assert state["contexts"]["page-00000"]["base"] == "https://example.com/base/"
    assert not state["pending"]


def test_discovery_lazy_imports_cycles_and_late_documents(jobs, event):
    chunk = script(event)
    entry = event(url="https://example.com/entry.js", mime="text/javascript", body="import '/app.js'")
    page = event(body='<script src="/entry.js"></script>')
    for capture in [chunk, entry, page]:
        jobs.artifacts.register(capture)
    jobs.artifacts.references(entry["id"], [chunk["data"]["url"]])
    jobs.artifacts.references(chunk["id"], [entry["data"]["url"]])
    jobs.artifacts.references(page["id"], [entry["data"]["url"]])
    key = jobs.enqueue(chunk, chunk, False)
    state = jobs.load(key)
    jobs.discover(state)
    assert state["stage"] == "extract" and list(state["contexts"]) == [page["id"]]
    late = event(url="https://example.com/late", body="page")
    jobs.artifacts.register(late)
    jobs.artifacts.references(late["id"], [chunk["data"]["url"]])
    key = jobs.enqueue(chunk, {"reanalysis_ticket": "new-ticket"}, False)
    state = jobs.load(key)
    jobs.discover(state)
    assert set(state["contexts"]) == {late["id"], page["id"]}


def test_restart_and_publication_wait_for_complete_plan(jobs, event):
    capture = script(event)
    jobs.artifacts.register(capture)
    key = jobs.enqueue(capture, capture, False)
    store = MagicMock()
    store.read.return_value = []
    extractor = MagicMock(side_effect=lambda *args, **kwargs: extract(
        *args, **kwargs, javascript_runner=lambda *args: {"nodes": [], "edges": []}
    ))
    assert jobs.step(key, store, extractor=extractor) is None
    assert jobs.load(key)["stage"] == "extract"
    jobs.step(key, store, extractor=extractor)
    assert jobs.load(key)["stage"] == "planning"
    store.publish.assert_not_called()
    jobs.connection.execute("UPDATE graph_continuations SET state='running'")
    jobs.connection.commit()
    resumed = Continuations(jobs.artifacts)
    resumed.recover()
    assert resumed.ready() == key
    resumed.step(key, store, extractor=extractor)
    assert resumed.load(key)["stage"] == "publish"
    store.publish.assert_not_called()
    resumed.step(key, store, extractor=extractor)
    state = resumed.step(key, store, extractor=extractor)
    assert state["stage"] == "reconcile" and extractor.call_count == 1
    assert store.publish.call_args.args[0].planned_links == {}
    resumed.finish(key, state)
    assert resumed.ready() is None and resumed.load(key)["stage"] == "complete"


def test_transient_failures_keep_retrying_conflicts_replan_and_checkpoint_version(jobs, event, monkeypatch):
    capture = script(event)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    projection = Projection(capture)
    projection.library_analysis = "summary"
    base = jobs.artifacts.write("base", projection.__dict__)
    state.update(stage="planning", projection=projection.__dict__, base_projection=str(base))
    jobs.save(key, state)
    monkeypatch.setattr(LinkPlanner, "plan_slice", MagicMock(side_effect=timeout()))
    for attempt, delay in enumerate([5, 30, 120, 120, 120]):
        before = continuations.time.time()
        jobs.step(key, MagicMock())
        row = jobs.connection.execute(
            "SELECT state,retries,next_attempt FROM graph_continuations WHERE id=?", (key,)
        ).fetchone()
        assert row[0] == "pending" and row[1] == attempt + 1 and row[2] >= before + delay
        assert jobs.ready() is None
        assert jobs.connection.execute("SELECT status FROM work").fetchone()[0] == "pending"
    monkeypatch.setattr(LinkPlanner, "plan_slice", MagicMock(side_effect=PublicationConflict("stale")))
    jobs.step(key, MagicMock())
    assert "planner" not in jobs.load(key) and jobs.load(key)["stage"] == "planning"
    state = jobs.load(key)
    state["version"] = 999
    jobs.save(key, state)
    with pytest.raises(ValueError, match="version"):
        jobs.load(key)


def test_fatal_extraction_and_unknown_stage_remain_failed(jobs, event):
    capture = script(event)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    state["stage"] = "extract"
    jobs.save(key, state)
    jobs.step(key, MagicMock(), extractor=MagicMock(side_effect=ValueError("bad source")))
    assert jobs.connection.execute("SELECT state,error FROM graph_continuations").fetchone() == (
        "failed", "ValueError: bad source"
    )
    state["stage"] = "unknown"
    jobs.save(key, state)
    jobs.step(key, MagicMock())
    assert "Unknown graph continuation stage" in jobs.connection.execute(
        "SELECT error FROM graph_continuations"
    ).fetchone()[0]


def test_eligibility_and_fair_ready_order(jobs, event, monkeypatch):
    assert not jobs.eligible(event()) and not jobs.eligible(event(body="page"))
    assert jobs.eligible(script(event))
    assert jobs.eligible(event(url="https://example.com/a.js.map", body="{}"))
    clock = [100.0]
    monkeypatch.setattr(continuations.time, "time", lambda: clock[0])
    first = script(event)
    key = jobs.enqueue(first, first, False)
    clock[0] = 101
    other = event(url="https://example.com/b.js", body="script", mime="text/javascript")
    second = jobs.enqueue(other, other, False)
    assert jobs.ready() == key
    clock[0] = 102
    jobs.save(key, jobs.load(key))
    assert jobs.ready() == second


def projection(event, count=1, selectors=1):
    graph = Projection(script(event))
    graph.contexts = [{"id": f"page-{index:05}", "url": "https://example.com/page"} for index in range(count)]
    page = graph.resource(graph.url)
    for index in range(selectors):
        node = graph.node("symbol", f"selector-{index}", capture_id=graph.event["id"], selector="#search")
        graph.fact(page, node, "CONTAINS", "test")
    return graph


class MatchingStore:
    def __init__(self):
        self.selection = self.hydration = 0
        self.contexts = set()

    def read(self, statement, **parameters):
        assert 0 < parameters.pop("timeout") <= 30
        if "contexts" in parameters:
            self.selection += 1
            self.contexts.update(parameters["contexts"])
            assert "USING INDEX other:GraphEntity(capture_id)" in statement
            assert parameters["selectors"] == ["#search"]
            return [{"id": key, "context": key} for key in parameters["contexts"]
                    if (key, key) > (parameters["after_context"], parameters["after_id"])][:parameters["limit"]]
        self.hydration += 1
        return [{"node": {"id": key, "kind": "element", "html_id": "search", "capture_id": key},
                 "evidence_id": "proof", "contexts": []} for key in parameters["ids"]]


def test_12538_contexts_finish_in_bounded_batches_and_group_selectors(event):
    graph = projection(event, count=12538)
    store = MatchingStore()
    planner = LinkPlanner(store, graph)
    slices = 0
    while True:
        before = planner.cursor["context"]
        done = planner.plan_slice()
        assert planner.cursor["context"] - before <= 100
        slices += 1
        if done:
            break
    assert slices == 126 and len(store.contexts) == 12538
    assert store.selection == store.hydration == 126
    assert len(planner.links) == 12538
    grouped = LinkPlanner(MatchingStore(), projection(event, count=10, selectors=200))
    assert grouped.plan_slice()
    assert grouped.store.selection == grouped.store.hydration == 1
    assert len(grouped.links) == 2000


def test_checkpoint_resumes_selected_page_without_repeating_selection(event):
    graph = projection(event, count=3)
    store = MatchingStore()
    planner = LinkPlanner(store, graph)
    assert not planner.plan_slice(reads=1)
    state = json.loads(json.dumps(planner.checkpoint()))
    assert state["cursor"]["selected"] and store.selection == 1 and store.hydration == 0
    assert 0 < state["operation"]["parameters"]["timeout"] <= 30
    restored = LinkPlanner(store, graph)
    restored.restore(state)
    assert restored.plan_slice()
    assert store.selection == store.hydration == 1 and len(restored.links) == 3
    with pytest.raises(ValueError, match="Unknown"):
        restored.restore({"not_trusted": 1})


def test_timeout_hydration_splits_but_irreducible_timeout_propagates(event):
    graph = projection(event, count=3)
    store = MatchingStore()
    read = store.read

    def smaller(statement, **parameters):
        if len(parameters.get("ids", [])) > 1:
            raise timeout()
        return read(statement, **parameters)

    store.read = smaller
    planner = LinkPlanner(store, graph)
    assert planner.plan_slice() and len(planner.links) == 3
    store.read = MagicMock(side_effect=timeout())
    with pytest.raises(Neo4jError):
        LinkPlanner(store, graph).plan_slice()


def test_local_modules_forms_and_time_budget_match_legacy(event, monkeypatch):
    graph = projection(event)
    clock = [0.0]
    monkeypatch.setattr(links.time, "monotonic", lambda: clock[0])
    planner = LinkPlanner(MatchingStore(), graph)
    original = planner.module_node

    def slow(node):
        original(node)
        clock[0] += 31

    monkeypatch.setattr(planner, "module_node", slow)
    assert not planner.plan_slice() and planner.cursor["node"] == 1
    assert planner.plan_slice() is False


def test_projection_checkpoint_interns_context_arrays_and_round_trips(event):
    from shyhurricane.graph.model import projection_snapshot, restore_projection

    graph = projection(event, count=100)
    urls = [item["url"] for item in graph.contexts]
    graph.nodes["a"] = {"id": "a", "context_urls": urls}
    graph.nodes["b"] = {"id": "b", "context_urls": list(urls)}
    graph.evidence["proof"] = {"id": "proof", "context_urls": []}
    state = projection_snapshot(graph)
    assert len(state["_context_lists"]) == 2
    restored = restore_projection(json.loads(json.dumps(state)))
    assert restored.__dict__ == graph.__dict__
    assert restored.nodes["a"]["context_urls"] is restored.nodes["b"]["context_urls"]
    graph.nodes = dict(reversed(list(graph.nodes.items())))
    assert projection_snapshot(graph) == state


def test_corrupt_checkpoint_does_not_stop_other_jobs(jobs, event):
    capture = script(event)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    state["version"] = 999
    jobs.save(key, state)
    assert jobs.step(key, MagicMock()) is None
    assert jobs.connection.execute("SELECT state,error FROM graph_continuations").fetchone() == (
        "failed", "Unsupported graph continuation checkpoint version"
    )


def test_reconciliation_is_paged_idempotent_and_preserves_chain(jobs, event):
    from shyhurricane.graph.scheduling import ReanalysisScheduler

    capture = script(event)
    jobs.artifacts.register(capture)
    for index in range(105):
        target = event(url=f"https://example.com/page/{index}")
        jobs.artifacts.register(target)
        jobs.artifacts.references(target["id"], [capture["data"]["url"]])
    queue = MagicMock()
    scheduler = ReanalysisScheduler(jobs.artifacts, queue)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    assert not jobs.reconcile(key, state, scheduler)
    assert jobs.connection.execute("SELECT count(*) FROM reanalysis").fetchone()[0] == 100
    # Replay the same slice after a crash before its checkpoint pointer committed.
    replay = jobs.load(key)
    assert not jobs.reconcile(key, replay, scheduler)
    assert jobs.connection.execute("SELECT max(generation) FROM reanalysis").fetchone()[0] == 1
    assert jobs.reconcile(key, state, scheduler)
    assert jobs.connection.execute("SELECT count(*) FROM reanalysis").fetchone()[0] == 105
    assert jobs.reconcile(key, {**state, "event": {**capture, "reconcile_remaining": 0}}, scheduler)


def test_reconciliation_pages_targets_and_handles_source_maps(jobs, event):
    from shyhurricane.graph.scheduling import ReanalysisScheduler

    capture = script(event)
    target = event(url="https://example.com/target.js", body="target", mime="text/javascript")
    jobs.artifacts.register(capture)
    jobs.artifacts.register(target)
    jobs.artifacts.references(capture["id"], [target["data"]["url"]])
    scheduler = ReanalysisScheduler(jobs.artifacts, MagicMock())
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    state["event"] = {**capture, "reconcile": True}
    assert jobs.reconcile(key, state, scheduler)
    assert jobs.connection.execute("SELECT capture_id FROM reanalysis").fetchone()[0] == target["id"]
    mapped = event(url="https://example.com/target.js.map", body="{}", mime="application/json")
    state = {"event": mapped}
    assert jobs.reconcile("map", state, scheduler)
    assert not state["reconciliation"]["urls"]


def test_scheduler_recovery_does_not_requeue_owned_jobs_and_finishes_failed_tickets(jobs, event):
    from shyhurricane.graph.scheduling import ReanalysisScheduler

    capture = jobs.artifacts.register(script(event))
    queue = MagicMock()
    scheduler = ReanalysisScheduler(jobs.artifacts, queue)
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    item = queue.put.call_args.args[0]
    queued = scheduler.claim(item)
    key = jobs.enqueue(queued, item, False)
    scheduler.recover()
    assert jobs.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == "running"
    jobs.save(key, jobs.load(key), status="failed")
    scheduler.recover()
    assert jobs.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == "failed"


def test_worker_alternates_normal_work_and_continuations(jobs, event, monkeypatch):
    from shyhurricane.graph import worker

    capture = script(event)
    pages = [event(url=f"https://example.com/page/{index}") for index in range(2)]
    for item in [capture, *pages]:
        jobs.artifacts.register(item)
    queue, store = MagicMock(), MagicMock()
    store.read.return_value = []
    order, extractions = [], []
    step = Continuations.step

    def record_step(self, key, database, **kwargs):
        order.append(self.load(key)["stage"])
        return step(self, key, database, **kwargs)

    def extractor(current, *args, **kwargs):
        extractions.append(current["id"])
        graph = Projection(current)
        graph.library_analysis = "summary"
        return graph

    store.publish.side_effect = lambda graph: order.append(graph.event["id"])
    monkeypatch.setattr(Continuations, "step", record_step)
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    monkeypatch.setattr(worker, "get_persistent_queue", lambda *args, **kwargs: queue)
    monkeypatch.setattr(worker, "GraphStore", lambda *args: store)
    monkeypatch.setattr(worker, "extract", extractor)
    monkeypatch.setattr(worker, "persistent_queue_get", lambda *args, **kwargs: iter([capture, *pages, capture]))
    monkeypatch.setattr("shyhurricane.index.web_resources._wait_for_health", lambda *args: True)
    worker.graph_worker("db", "bolt://test", MagicMock(), MagicMock(), False)
    assert order[:4] == ["discovery", pages[0]["id"], "extract", pages[1]["id"]]
    assert extractions.count(capture["id"]) == 1 and store.publish.call_count == 3
    assert queue.ack.call_count == 4
    assert jobs.connection.execute("SELECT state FROM graph_continuations").fetchone()[0] == "done"
    assert jobs.connection.execute("SELECT status FROM work WHERE id=?", (capture["id"],)).fetchone()[0] == "complete"


def test_resumable_planner_preserves_local_module_and_form_links(event):
    from shyhurricane.graph.model import projection_snapshot, restore_projection

    graph = Projection(event())
    capture = graph.event["id"]
    graph.contexts = [{"id": capture, "url": graph.url}]
    page = graph.resource(graph.url)
    importer = graph.node("parameter", "caller", capture_id=capture, import_key="api", imported_name="go",
                          parameter_index=0)
    exporter = graph.node("parameter", "export", capture_id=capture, module_key="api", export_names=["go"],
                          parameter_index=0)
    selector = graph.node("symbol", "selector", capture_id=capture, selector="#form", form_request=True)
    graph.node("element", "form", capture_id=capture, html_id="form", html_tag="form",
               form_target_url="https://example.com/save", form_target_method="POST")
    for key in [importer, exporter, selector]:
        graph.fact(page, key, "CONTAINS", "test")
    clone = restore_projection(projection_snapshot(graph))
    store = MagicMock()
    store.read.return_value = []
    legacy = LinkPlanner(store, graph).plan()
    planner = LinkPlanner(store, clone)
    assert planner.plan_slice()
    assert planner.links == legacy
    assert any(edge["kind"] == "REQUESTS" for edge in planner.links.values())


def test_context_selection_splits_timeouts_and_preserves_cursor(event):
    graph = projection(event, count=3)
    store = MatchingStore()
    read = store.read

    def smaller(statement, **parameters):
        if parameters.get("limit", 0) > 1:
            raise timeout()
        return read(statement, **parameters)

    store.read = smaller
    planner = LinkPlanner(store, graph)
    assert planner.plan_slice() and len(planner.links) == 3
    assert planner.cursor["after_context"] == planner.cursor["after_id"] == ""
    store.read = MagicMock(side_effect=Neo4jError._hydrate_neo4j(
        code="Neo.ClientError.Statement.SyntaxError", message="bad query"
    ))
    with pytest.raises(Neo4jError):
        LinkPlanner(store, graph).plan_slice()


def test_failed_checkpoint_write_keeps_previous_committed_pointer(jobs, event, monkeypatch):
    capture = script(event)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    old = jobs.connection.execute("SELECT checkpoint FROM graph_continuations").fetchone()[0]
    original = jobs.artifacts.write

    def interrupted(name, value):
        original(name, value)
        raise OSError("crash before pointer commit")

    monkeypatch.setattr(jobs.artifacts, "write", interrupted)
    state["stage"] = "extract"
    with pytest.raises(OSError, match="pointer"):
        jobs.save(key, state)
    assert jobs.connection.execute("SELECT checkpoint FROM graph_continuations").fetchone()[0] == old
    assert jobs.load(key)["stage"] == "discovery"


def test_completed_job_compacts_state_and_supersedes_prior_failure(jobs, event):
    capture = script(event)
    first = jobs.enqueue(capture, capture, False)
    jobs.save(first, jobs.load(first), status="failed")
    key = jobs.enqueue(capture, {"reanalysis_ticket": "retry"}, False)
    state = jobs.load(key)
    state["projection"] = {"large": "temporary"}
    state["planner"] = {"cursor": {"context": 2}}
    state["contexts"] = {"one": {}, "two": {}}
    jobs.finish(key, state)
    complete = jobs.load(key)
    assert "projection" not in complete and "contexts" not in complete
    assert complete["contexts_total"] == complete["contexts_completed"] == 2
    prior = jobs.connection.execute("SELECT state FROM graph_continuations WHERE id=?", (first,)).fetchone()[0]
    assert prior == "superseded"


def test_partial_hydration_survives_yield_without_repeating_completed_ids(event):
    graph = projection(event, count=3)
    store = MatchingStore()
    read = store.read
    singles = []

    def split(statement, **parameters):
        ids = parameters.get("ids")
        if ids and len(ids) > 1:
            raise timeout()
        if ids:
            singles.extend(ids)
        return read(statement, **parameters)

    store.read = split
    planner = LinkPlanner(store, graph)
    assert not planner.plan_slice(reads=3)
    saved = json.loads(json.dumps(planner.checkpoint()))
    assert len(saved["hydrated"]) == 1
    restored = LinkPlanner(store, graph)
    restored.restore(saved)
    assert restored.plan_slice() and len(restored.links) == 3
    assert len(singles) == len(set(singles)) == 3


def test_candidate_page_resume_and_timeout_reduction(event):
    from shyhurricane.graph.links import PlanningYield

    calls = []

    def read(statement, **parameters):
        calls.append(parameters)
        if "ids" in parameters:
            return [{"node": {"id": key}, "evidence_id": "proof", "contexts": []}
                    for key in parameters["ids"]]
        return [{"id": key} for key in ["a", "b", "c"] if key > parameters["after"]][:parameters["limit"]]

    store = MagicMock()
    store.read.side_effect = read
    planner = LinkPlanner(store, projection(event))
    planner.checkpointing, planner.reads_left = True, 1
    with pytest.raises(PlanningYield):
        planner.candidates("module_key", "api")
    saved = json.loads(json.dumps(planner.checkpoint()))
    restored = LinkPlanner(store, planner.graph)
    restored.restore(saved)
    assert len(restored.candidates("module_key", "api")) == 3
    assert len(calls) == 2

    def smaller(statement, **parameters):
        if parameters.get("limit", 0) > 1:
            raise timeout()
        return read(statement, **parameters)

    store.read.side_effect = smaller
    assert len(LinkPlanner(store, planner.graph).candidates("selector", "#search")) == 3


def test_relocated_legacy_checkpoints_resume_and_cleanup(jobs, event, monkeypatch):
    capture = script(event)
    page = event(body='<script src="/app.js"></script>')
    jobs.artifacts.register(page)
    jobs.artifacts.references(page["id"], [capture["data"]["url"]])
    key = jobs.enqueue(capture, capture, False)
    checkpoint = jobs.connection.execute("SELECT checkpoint FROM graph_continuations").fetchone()[0]
    assert checkpoint == jobs.artifacts.resolve(checkpoint).name
    state = jobs.load(key)
    projection = jobs.artifacts.write("base", Projection(capture).__dict__)
    state["base_projection"] = str(projection)
    jobs.save(key, state)
    assert jobs.load(key)["base_projection"] == projection.name
    # Emulate legacy absolute references in both SQLite and the checkpoint JSON.
    old_root = jobs.artifacts.root
    checkpoint = jobs.connection.execute("SELECT checkpoint FROM graph_continuations").fetchone()[0]
    state["base_projection"] = str(projection)
    jobs.artifacts.resolve(checkpoint).write_text(json.dumps(state))
    jobs.connection.execute("UPDATE graph_continuations SET checkpoint=?", (str(old_root / checkpoint),))
    jobs.connection.execute("UPDATE captures SET path=?", (str(old_root / jobs.connection.execute(
        "SELECT path FROM captures"
    ).fetchone()[0]),))
    jobs.connection.commit()
    jobs.artifacts.close()
    moved = old_root.with_name("moved")
    old_root.rename(moved)
    monkeypatch.chdir(moved.parent)
    monkeypatch.setattr("shyhurricane.graph.artifacts.persistent_queue_path", lambda *args: moved)
    jobs.artifacts = ArtifactStore("db")
    jobs.connection = jobs.artifacts.connection
    loaded = jobs.load(key)
    jobs.discover(loaded)
    assert page["id"] in loaded["contexts"]
    jobs.save(key, loaded)
    assert not (moved / checkpoint).exists()
    assert jobs.load(key)["base_projection"] == projection.name
    jobs.finish(key, loaded)
    assert not (moved / projection.name).exists()
    assert jobs.load(key)["stage"] == "complete"


def test_discovery_includes_standalone_svg_document(jobs, event):
    capture = script(event)
    svg = event(url="https://example.com/drawing.svg", mime="image/svg+xml; charset=utf-8",
                body="<svg><script href='/app.js'/></svg>")
    for item in [capture, svg]:
        jobs.artifacts.register(item)
    extract(svg, jobs.artifacts)
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    jobs.discover(state)
    assert state["stage"] == "extract"
    assert state["contexts"] == {
        svg["id"]: {"id": svg["id"], "url": svg["data"]["url"], "base": svg["data"]["url"]},
    }
