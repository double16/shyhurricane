import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.continuations import Continuations
from shyhurricane.graph.scheduling import ReanalysisScheduler
from shyhurricane.persistent_queue import get_persistent_queue


@pytest.fixture
def scheduling(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    scheduler = ReanalysisScheduler(artifacts, queue)
    yield scheduler, artifacts, queue, capture
    queue.close()
    artifacts.close()


def test_pending_requests_merge_routes_and_preserve_capture_versions(scheduling, event):
    scheduler, artifacts, queue, capture = scheduling
    for index in range(100):
        scheduler.request(capture["id"], ["root", str(index)], index % 31)
        scheduler.flush()
    assert queue.qsize() == 1
    item = queue.get(block=False)
    claimed = scheduler.claim(item)
    assert claimed["reconcile_chain"] == ["root"]
    assert claimed["reconcile_remaining"] == 30
    assert claimed["data"] == capture["data"]
    assert scheduler.claim(item) is None
    other = artifacts.register(event(body="new version"))
    scheduler.request(other["id"], ["root"], 1)
    scheduler.flush()
    assert queue.get(block=False)["id"] == other["id"]


def test_requests_during_processing_produce_one_followup(scheduling):
    scheduler, artifacts, queue, capture = scheduling
    scheduler.request(capture["id"], ["first"], 1)
    scheduler.flush()
    item = queue.get(block=False)
    assert scheduler.claim(item)
    for index in range(50):
        scheduler.request(capture["id"], ["new", str(index)], 7)
    scheduler.flush()
    assert queue.qsize() == 0
    scheduler.finish(item)
    queue.ack(item)
    scheduler.flush()
    assert queue.qsize() == 1
    followup = queue.get(block=False)
    assert followup["reanalysis_ticket"] != item["reanalysis_ticket"]
    assert scheduler.claim(item) is None
    event = scheduler.claim(followup)
    assert event["reconcile_chain"] == ["new"]
    assert event["reconcile_remaining"] == 7
    scheduler.finish(followup)
    scheduler.finish(followup)
    queue.ack(followup)
    scheduler.flush()
    assert queue.qsize() == 0
    assert scheduler.claim(followup) is None
    # A genuinely later update starts a new ticket, even after previous work completed.
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    assert scheduler.claim(queue.get(block=False))["reconcile_remaining"] == 0


def test_recovery_covers_undelivered_and_interrupted_work(scheduling):
    scheduler, artifacts, queue, capture = scheduling
    scheduler.request(capture["id"], ["root", "a"], 2)
    scheduler.recover()  # Request committed before queue delivery.
    item = queue.get(block=False)
    scheduler.claim(item)
    scheduler.request(capture["id"], ["root", "b"], 5)
    scheduler.recover()  # Worker died after claim or publication, before completion.
    duplicate = queue.get(block=False)
    event = scheduler.claim(duplicate)
    assert event["reconcile_chain"] == ["root"]
    assert event["reconcile_remaining"] == 5
    scheduler.finish(duplicate)
    assert scheduler.claim(item) is None


def test_delivery_ack_window_is_safe_and_retry_keeps_new_requests(scheduling):
    scheduler, artifacts, queue, capture = scheduling
    scheduler.request(capture["id"], ["a"], 2)
    scheduler.flush()
    # Simulate a crash after queue.put but before the delivered flag committed.
    with artifacts.connection:
        artifacts.connection.execute("UPDATE reanalysis SET delivered=0")
    scheduler.recover()
    first, duplicate = queue.get(block=False), queue.get(block=False)
    assert first == duplicate
    scheduler.claim(first)
    scheduler.request(capture["id"], ["b"], 3)
    scheduler.retry(first)
    queue.nack(first)
    assert scheduler.claim(first)["reconcile_chain"] == []
    scheduler.finish(first)
    scheduler.retry(first)  # Completion before acknowledgement must not resurrect it.
    assert scheduler.claim(duplicate) is None


def test_failed_delivery_remains_recoverable(scheduling):
    scheduler, artifacts, queue, capture = scheduling
    scheduler.request(capture["id"], [], 0)
    broken = ReanalysisScheduler(artifacts, MagicMock())
    broken.queue.put.side_effect = OSError("disk full")
    with pytest.raises(OSError):
        broken.flush()
    scheduler.recover()
    assert scheduler.claim(queue.get(block=False))


def test_old_failed_continuation_does_not_block_new_ticket_recovery(scheduling):
    scheduler, artifacts, queue, capture = scheduling
    jobs = Continuations(artifacts)
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    old_receipt = queue.get(block=False, raw=True)
    old_item = old_receipt["data"]
    old_event = scheduler.claim(old_item)
    old_key = jobs.enqueue(old_event, old_item, False)
    jobs.save(old_key, jobs.load(old_key), status="failed")
    scheduler.retry(old_item, failed=True)
    queue.ack_failed(old_receipt)
    scheduler.request(capture["id"], [], 2)
    scheduler.flush()
    interrupted = queue.get(block=False, raw=True)
    assert scheduler.claim(interrupted["data"])
    # Crash after claiming the new ticket, before its continuation is committed.
    queue.resume_unack_tasks()
    replacement = ReanalysisScheduler(artifacts, queue)
    replacement.recover()
    replacement.recover()
    assert queue.acked_count() == 0 and queue.ack_failed_count() == 1
    receipt = queue.get(block=False, raw=True)
    recovered = replacement.claim(receipt["data"])
    assert recovered is not None and recovered["reconcile_remaining"] == 2
    assert receipt["data"]["reanalysis_ticket"] != old_item["reanalysis_ticket"]
    replacement.finish(receipt["data"])
    queue.ack(receipt)
    while queue.ready_count():
        duplicate = queue.get(block=False, raw=True)
        assert replacement.claim(duplicate["data"]) is None
        queue.ack(duplicate)
    assert queue.ready_count() == queue.unack_count() == 0
    assert queue.ack_failed_count() == 1
    assert artifacts.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == "done"


@pytest.mark.parametrize("state", ["pending", "running", "failed"])
def test_matching_continuation_keeps_ownership_during_recovery(scheduling, state):
    scheduler, artifacts, queue, capture = scheduling
    jobs = Continuations(artifacts)
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    item = queue.get(block=False)
    claimed = scheduler.claim(item)
    key = jobs.enqueue(claimed, item, False)
    jobs.save(key, jobs.load(key), status=state)
    scheduler.recover()
    scheduler.recover()
    expected = "failed" if state == "failed" else "running"
    assert artifacts.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == expected
    assert queue.ready_count() == queue.acked_count() == 0


@pytest.mark.parametrize("rebuild", [False, True])
def test_failed_publication_waits_for_explicit_retry_or_rebuild(scheduling, rebuild):
    scheduler, artifacts, queue, capture = scheduling
    scheduler.request(capture["id"], [], 0)
    scheduler.flush()
    receipt = queue.get(block=False, raw=True)
    item = receipt["data"]
    scheduler.claim(item)
    scheduler.retry(item, failed=True)
    queue.ack_failed(receipt)
    scheduler.recover()
    assert queue.ready_count() == 0 and queue.ack_failed_count() == 1
    assert artifacts.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == "failed"
    if rebuild:
        scheduler.request(capture["id"], [], 0)
        scheduler.flush()
        assert scheduler.claim(item) is None
    else:
        queue.nack(id=receipt["pqid"])
    retried = queue.get(block=False, raw=True)
    assert (retried["data"]["reanalysis_ticket"] != item["reanalysis_ticket"]) is rebuild
    assert scheduler.claim(retried["data"])["id"] == capture["id"]
    scheduler.finish(retried["data"])
    queue.ack(retried)
    assert artifacts.connection.execute("SELECT state FROM reanalysis").fetchone()[0] == "done"


@pytest.mark.parametrize("remaining,visited", [(-1, []), (31, []), (0, ["self"])])
def test_reject_invalid_routes(scheduling, remaining, visited):
    scheduler, _, _, _ = scheduling
    with pytest.raises(ValueError):
        scheduler.request("self", visited, remaining)


def test_missing_capture_fails_and_can_be_finalized(scheduling):
    scheduler, _, queue, _ = scheduling
    scheduler.request("missing", [], 0)
    scheduler.flush()
    item = queue.get(block=False)
    with pytest.raises(ValueError, match="unavailable"):
        scheduler.claim(item)
    scheduler.finish(item)
    assert scheduler.claim(item) is None


def test_concurrent_producers_coalesce_atomically(scheduling):
    scheduler, _, _, capture = scheduling
    transport = MagicMock()

    def request(index):
        artifacts = ArtifactStore("db")
        try:
            producer = ReanalysisScheduler(artifacts, transport)
            producer.request(capture["id"], ["root", str(index)], index % 31)
            producer.flush()
        finally:
            artifacts.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(request, range(50)))
    scheduler.flush()
    assert transport.put.call_count == 1
    row = scheduler.connection.execute("SELECT generation,pending FROM reanalysis").fetchone()
    assert row[0] == 50
    assert json.loads(row[1]) == {"visited": ["root"], "remaining": 30}


def test_opening_graph_producer_does_not_reclaim_a_live_task(scheduling):
    _, _, queue, capture = scheduling
    queue.put(capture)
    queue.get(block=False)
    producer = get_persistent_queue("db", "graph_queue", auto_resume=False)
    try:
        assert producer.unack_count() == 1
        assert producer.ready_count() == 0
    finally:
        producer.close()


def test_cycle_merges_cannot_replenish_remaining_hops(scheduling, event):
    scheduler, artifacts, queue, a = scheduling
    b = artifacts.register(event(url="https://example.com/b"))
    scheduler.request(a["id"], [], 3)
    processed = []
    while True:
        scheduler.flush()
        if not queue.qsize():
            break
        item = queue.get(block=False)
        current = scheduler.claim(item)
        processed.append(current["reconcile_remaining"])
        remaining = current["reconcile_remaining"]
        if remaining:
            target = b if current["id"] == a["id"] else a
            # Distinct chains intersect to nothing; only the explicit budget bounds this cycle.
            scheduler.request(target["id"], ["left"], remaining - 1)
            scheduler.request(target["id"], ["right"], remaining - 1)
        scheduler.finish(item)
        queue.ack(item)
    assert processed == [3, 2, 1, 0]


def test_reopening_scheduler_recovers_committed_outbox(scheduling):
    scheduler, _, queue, capture = scheduling
    scheduler.request(capture["id"], ["root"], 2)
    reopened = ArtifactStore("db")
    try:
        replacement = ReanalysisScheduler(reopened, queue)
        replacement.recover()
        assert replacement.claim(queue.get(block=False))["data"] == capture["data"]
    finally:
        reopened.close()


@pytest.mark.parametrize("newer", [False, True])
def test_restart_after_completion_before_acknowledgement(scheduling, newer):
    scheduler, _, queue, capture = scheduling
    scheduler.request(capture["id"], ["root"], 1)
    scheduler.flush()
    old = queue.get(block=False)
    scheduler.claim(old)
    if newer:
        scheduler.request(capture["id"], ["new"], 2)
    scheduler.finish(old)  # Publication and scheduling committed; queue acknowledgement did not.
    artifacts = ArtifactStore("db")
    restarted_queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    try:
        replacement = ReanalysisScheduler(artifacts, restarted_queue)
        restarted_queue.resume_unack_tasks()
        replacement.recover()
        stale = restarted_queue.get(block=False)
        assert replacement.claim(stale) is None
        restarted_queue.ack(stale)
        if newer:
            item = restarted_queue.get(block=False)
            assert replacement.claim(item)["reconcile_chain"] == ["new"]
            replacement.finish(item)
            restarted_queue.ack(item)
        assert restarted_queue.ready_count() == restarted_queue.unack_count() == 0
    finally:
        restarted_queue.close()
        artifacts.close()


def test_claim_uses_opaque_capture_reference(scheduling, tmp_path):
    scheduler, artifacts, queue, capture = scheduling
    reference = artifacts.connection.execute("SELECT path FROM captures").fetchone()[0]
    assert reference.startswith("a:")
    scheduler.request(capture["id"], ["root"], 1)
    scheduler.flush()
    assert scheduler.claim(queue.get(block=False))["data"] == capture["data"]
