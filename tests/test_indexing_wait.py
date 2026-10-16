"""Indexing waits stay scoped, bounded, cancellable and explicit about incomplete results."""

import argparse
import asyncio
import json
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from haystack import Document

from shyhurricane import indexing_wait as waiting
from shyhurricane.persistent_queue import open_persistent_queue
from shyhurricane.server_config import ServerConfig


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(waiting, "persistent_queue_path", lambda db, name: tmp_path / name)
    monkeypatch.setattr(waiting, "get_server_config", lambda: ServerConfig(indexing_wait_timeout_seconds=0.08))
    monkeypatch.setattr(waiting, "POLL_SECONDS", 0.002)
    monkeypatch.setattr(waiting, "PROGRESS_SECONDS", 0.005)
    monkeypatch.setattr(waiting, "_budget", waiting.ContextVar("test_budget", default=None))
    server = SimpleNamespace(db="test", low_power=False)
    ctx = SimpleNamespace(report_progress=AsyncMock())
    queues = {}

    def queue(name):
        if name not in queues:
            queues[name] = open_persistent_queue(str(tmp_path / name), auto_resume=False)
        return queues[name]

    yield server, ctx, queue
    for value in queues.values():
        value.close()


def enqueue(queue, url="https://example.com/app"):
    return queue.put(json.dumps({"request": {"endpoint": url}}))


@pytest.mark.parametrize("value", ["0", "0.25", "60"])
def test_timeout_valid(value):
    assert waiting.indexing_timeout(value) == float(value)


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "bad"])
def test_timeout_invalid(value):
    with pytest.raises(argparse.ArgumentTypeError):
        waiting.indexing_timeout(value)
    if value != "bad":
        with pytest.raises(ValueError):
            ServerConfig(indexing_wait_timeout_seconds=float(value))


@pytest.mark.parametrize(
    "scope,url,expected",
    [
        ("example.com", "https://a.example.com/app", True),
        ("example.com", "https://badexample.com/", False),
        ("example.com:443", "https://example.com/", True),
        ("example.com:443", "http://example.com/", False),
        ("https://example.com/app", "https://example.com/app/x", True),
        ("https://example.com/app", "https://example.com/other", False),
        ("https://example.com/app", "https://a.example.com/app", False),
        ("[::1]:8080", "http://[::1]:8080/", True),
    ],
)
def test_scope_matching(scope, url, expected):
    assert waiting.url_matcher([scope])(url) == expected


def test_exact_and_inventory_matchers():
    assert waiting.url_matcher(["https://EXAMPLE.com:443/a"], exact=True)("https://example.com/a")
    assert not waiting.url_matcher(["https://example.com/a"], exact=True)("https://example.com/ab")
    assert waiting.url_matcher([])("https://anything.test/")
    assert waiting.inventory_matcher("example", domains=True)("https://api.example.com/")
    assert waiting.inventory_matcher("example.com:443", path="admin")("https://api.example.com/admin")
    assert not waiting.inventory_matcher("example.com:443", path="admin")("https://api.example.com/login")
    assert not waiting.inventory_matcher("example.com:443")("http://api.example.com/")


async def test_unrelated_indexing_returns_immediately(environment):
    server, ctx, queue = environment
    enqueue(queue("ingest_queue"), "https://other.test/")
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]))
    assert result.status == "complete"
    ctx.report_progress.assert_not_awaited()


async def test_wait_completion_progress_and_scoped_handoff(environment):
    server, ctx, queue = environment
    ingest, documents = queue("ingest_queue"), queue("doc_type_queue")
    enqueue(ingest)
    item = ingest.get()

    async def finish():
        await asyncio.sleep(0.01)
        documents.put(Document(id="doc", meta={"url": "https://example.com/app"}))
        ingest.ack(item)
        doc = documents.get()
        await asyncio.sleep(0.01)
        documents.ack(doc)

    from shyhurricane.mcp_server.progress import progress_scope

    @progress_scope()
    async def run():
        task = asyncio.create_task(finish())
        result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]), semantic=True)
        await task
        return result

    result = await run()
    assert result.status == "complete"
    calls = ctx.report_progress.await_args_list
    assert [call.args[0] for call in calls] == list(range(1, len(calls) + 1))
    assert "Waiting for indexing" in calls[0].kwargs["message"]
    assert "querying available data" in calls[-1].kwargs["message"]


async def test_timeout_and_failed_items(environment):
    server, ctx, queue = environment
    ingest = queue("ingest_queue")
    enqueue(ingest)
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]))
    assert result.status == "timed_out"
    assert result.potentially_incomplete
    assert result.stages["ingest"]["pending"] == 1
    item = ingest.get()
    ingest.ack_failed(item)
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]))
    assert result.status == "failed"
    assert result.stages["ingest"]["failed"] == 1


async def test_paused_semantic_indexing_is_skipped(environment):
    server, ctx, queue = environment
    server.low_power = True
    queue("doc_type_queue").put(Document(id="doc", meta={"url": "https://example.com/app"}))
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]), semantic=True)
    assert result.status == "paused"
    assert result.skipped_stages == ["type_specific_index"]


async def test_unknown_scope_and_read_errors_are_unavailable(environment, monkeypatch):
    server, ctx, queue = environment
    queue("ingest_queue").put("not understood")
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]))
    assert result.status == "unavailable"
    monkeypatch.setattr(waiting, "read_indexing_status", lambda *args: (_ for _ in ()).throw(OSError("read")))
    result = await waiting.wait_for_indexing(ctx, server, lambda url: True)
    assert result.status == "unavailable"
    result = await waiting.wait_for_indexing(ctx, SimpleNamespace(), lambda url: True)
    assert result.status == "unavailable"


async def test_disabled_wait_does_not_read_queues(environment, monkeypatch):
    server, ctx, queue = environment
    monkeypatch.setattr(waiting, "get_server_config", lambda: ServerConfig(indexing_wait_timeout_seconds=0))
    monkeypatch.setattr(waiting, "read_indexing_status", lambda *args: pytest.fail("read queues"))
    result = await waiting.wait_for_indexing(ctx, server, lambda url: True)
    assert result.status == "disabled"


async def test_cancellation_does_not_acknowledge_work(environment):
    server, ctx, queue = environment
    enqueue(queue("ingest_queue"))
    task = asyncio.create_task(waiting.wait_for_indexing(ctx, server, lambda url: True))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert queue("ingest_queue").size == 1


async def test_nested_calls_share_budget_and_reset_afterwards(environment):
    server, ctx, queue = environment
    enqueue(queue("ingest_queue"))

    @waiting.indexing_scope()
    async def nested():
        return await waiting.wait_for_indexing(ctx, server, lambda url: True)

    @waiting.indexing_scope()
    async def request():
        first = await nested()
        second = await nested()
        assert first.waited_seconds == second.waited_seconds or second.waited_seconds - first.waited_seconds < 0.01
        assert second.status == "timed_out"

    await request()
    assert waiting._budget.get() is None


async def test_slow_status_reads_are_bounded(environment, monkeypatch):
    server, ctx, queue = environment

    def slow(*args):
        time.sleep(0.15)
        return {}, False

    monkeypatch.setattr(waiting, "read_indexing_status", slow)
    started = time.monotonic()
    result = await waiting.wait_for_indexing(ctx, server, lambda url: True)
    assert result.status == "timed_out"
    assert time.monotonic() - started < 0.14


async def test_progress_failures_do_not_fail_retrieval(environment):
    server, ctx, queue = environment
    ctx.report_progress.side_effect = RuntimeError("disconnected")
    enqueue(queue("ingest_queue"))
    assert (await waiting.wait_for_indexing(ctx, server, lambda url: True)).status == "timed_out"


def make_artifacts(path):
    path.mkdir()
    connection = sqlite3.connect(path / "artifacts.sqlite")
    connection.executescript(
        "CREATE TABLE captures(id TEXT,url TEXT); CREATE TABLE refs(capture_id TEXT,url TEXT);"
        "CREATE TABLE reanalysis(capture_id TEXT,state TEXT,delivered INTEGER);"
        "INSERT INTO captures VALUES ('page','https://example.com/app'),('script','https://cdn.test/app.js');"
        "INSERT INTO refs VALUES ('page','https://cdn.test/app.js');"
    )
    connection.commit()
    return connection


async def test_graph_dependencies_and_undelivered_outbox(environment, tmp_path):
    server, ctx, queue = environment
    artifacts = make_artifacts(tmp_path / "graph_state")
    queue("graph_queue").put({"id": "script", "reanalysis_ticket": "ticket"})
    counts, unknown = waiting.read_indexing_status(
        server,
        waiting.url_matcher(["example.com"]),
        ["ingest", "graph"],
        time.monotonic() + 1,
    )
    assert not unknown
    assert counts["graph"]["pending"] == 1
    item = queue("graph_queue").get()
    queue("graph_queue").ack(item)
    artifacts.execute("INSERT INTO reanalysis VALUES ('script','pending',0)")
    artifacts.commit()
    counts, unknown = waiting.read_indexing_status(
        server,
        waiting.url_matcher(["example.com"]),
        ["ingest", "graph"],
        time.monotonic() + 1,
    )
    assert counts["graph"]["pending"] == 1
    artifacts.execute("DELETE FROM reanalysis")
    artifacts.commit()
    result = await waiting.wait_for_indexing(ctx, server, waiting.url_matcher(["example.com"]), graph=True)
    assert result.status == "complete"
    artifacts.close()


def test_query_url_and_empty_scope_matching():
    matches = waiting.url_matcher(["", "https://example.com/search?q=a"])
    assert matches("https://example.com/search?q=a")
    assert not matches("https://example.com/search?q=b")
    assert not waiting.url_matcher(["not-a-url?x=1"])("https://example.com/")
    assert waiting.inventory_matcher(None)("http://example.com/")
    assert not waiting.inventory_matcher("other.test")("https://example.com/")


def test_document_ids_and_multi_resource_queue_counts(environment):
    server, ctx, queue = environment
    ingest = queue("ingest_queue")
    ingest.put(
        "\n".join(
            json.dumps({"request": {"endpoint": url}})
            for url in (
                "https://example.com/a",
                "https://example.com/b",
                "https://other.test/",
            )
        )
    )
    documents = queue("doc_type_queue")
    documents.put(Document(id="wanted", meta={"url": "https://example.com/a"}))
    documents.put(Document(id="other", meta={"url": "https://example.com/b"}))
    counts, unknown = waiting.read_indexing_status(
        server,
        waiting.url_matcher(["example.com"]),
        ["ingest", "type_specific_index"],
        time.monotonic() + 1,
    )
    assert not unknown
    assert counts["ingest"]["pending"] == 1
    counts, unknown = waiting.read_indexing_status(
        server,
        lambda url: False,
        ["ingest", "type_specific_index"],
        time.monotonic() + 1,
        doc_id="wanted",
    )
    assert unknown  # A missing opaque URI cannot be mapped to newly ingested URLs.
    assert counts["type_specific_index"]["pending"] == 1


def test_graph_cycles_missing_captures_and_legacy_scheduler(environment, tmp_path):
    server, ctx, queue = environment
    assert waiting._artifacts(server.db, lambda url: True, time.monotonic() + 1) == (set(), {}, [])
    artifacts = make_artifacts(tmp_path / "graph_state")
    artifacts.execute("INSERT INTO refs VALUES ('script','https://example.com/app')")
    artifacts.execute("INSERT INTO reanalysis VALUES ('missing','pending',0)")
    artifacts.execute("INSERT INTO reanalysis VALUES ('page','pending',0)")
    artifacts.execute("INSERT INTO captures VALUES ('other','https://other.test/')")
    artifacts.execute("INSERT INTO reanalysis VALUES ('other','pending',0)")
    artifacts.commit()
    queue("graph_queue").put({"id": "missing", "reanalysis_ticket": "ticket"})
    counts, unknown = waiting.read_indexing_status(
        server,
        waiting.url_matcher(["example.com"]),
        ["graph"],
        time.monotonic() + 1,
    )
    assert unknown
    assert counts["graph"]["pending"] == 1
    artifacts.execute("DROP TABLE reanalysis")
    artifacts.commit()
    urls, _, outbox = waiting._artifacts(server.db, waiting.url_matcher(["example.com"]), time.monotonic() + 1)
    assert urls == {"https://example.com/app", "https://cdn.test/app.js"}
    assert outbox == []
    with pytest.raises(TimeoutError):
        waiting._artifacts(server.db, lambda url: True, time.monotonic() - 1)
    artifacts.close()


def test_status_read_deadline_and_missing_scope_metadata(environment):
    server, ctx, queue = environment
    enqueue(queue("ingest_queue"))
    with pytest.raises(TimeoutError):
        waiting.read_indexing_status(server, lambda url: True, ["ingest"], time.monotonic() - 1)
    ingest = queue("ingest_queue")
    with ingest._putter as connection:
        connection.execute("DELETE FROM indexing_scope")
    _, unknown = waiting.read_indexing_status(server, lambda url: True, ["ingest"], time.monotonic() + 1)
    assert unknown


async def test_exhausted_budget_does_not_wait_again(environment):
    server, ctx, queue = environment
    budget = waiting.WaitBudget(remaining=0)
    token = waiting._budget.set(budget)
    try:
        result = await waiting.wait_for_indexing(ctx, server, lambda url: True)
        assert result.status == "timed_out"
        assert result.waited_seconds < 0.01
    finally:
        waiting._budget.reset(token)
