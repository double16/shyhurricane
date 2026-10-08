from threading import Event
from unittest.mock import Mock

import pytest

import shyhurricane.mcp_server.server_context as server_context
from shyhurricane.mcp_server.server_context import ServerContext, close_server_context


class Closeable:
    def __init__(self, fail=False):
        self.fail = fail
        self.closed = False
        self.items = []

    def cancel_join_thread(self):
        pass

    def close(self):
        if self.fail:
            raise RuntimeError("close failed")
        self.closed = True

    def put(self, item):
        if self.fail:
            raise RuntimeError("put failed")
        self.items.append(item)


def make_context(failing_queue=False):
    return ServerContext(
        db="db",
        cache_path="/tmp",
        document_pipeline=None,
        website_context_pipeline=None,
        ingest_queue=Closeable(failing_queue),
        ingest_pool=Closeable(),
        task_queue=Closeable(failing_queue),
        task_pool=Closeable(),
        spider_result_queue=Closeable(),
        port_scan_result_queue=Closeable(),
        dir_busting_result_queue=Closeable(),
        stores={},
        qdrant_client=None,
        mcp_session_volume="volume",
    )


def test_server_context_close_closes_pools_and_queues():
    ctx = make_context()

    ctx.close()

    assert ctx.task_pool.closed is True
    assert ctx.ingest_pool.closed is True
    assert ctx.ingest_queue.items == []
    assert ctx.task_queue.items == []
    assert ctx.spider_result_queue.items == []
    assert ctx.port_scan_result_queue.items == []
    assert ctx.ingest_queue.closed is True
    assert ctx.dir_busting_result_queue.closed is True


def test_server_context_close_swallows_queue_errors():
    ctx = make_context(failing_queue=True)

    ctx.close()

    assert ctx.task_pool.closed is True
    assert ctx.ingest_pool.closed is True


def test_context_shutdown_shares_deadline_and_is_idempotent(monkeypatch):
    ctx = make_context()
    ctx.stop_event = Event()
    ctx.task_pool = Mock()
    ctx.ingest_pool = Mock()
    ctx.worker_manager = Mock()
    ctx.health_monitor = Mock()
    cleanup = Mock()
    monkeypatch.setattr(server_context, "close_haystack_resources", cleanup)
    ctx.ingest_pool.close.side_effect = lambda **kwargs: cleanup.assert_not_called()
    monkeypatch.setattr(server_context.time, "monotonic", lambda: 10)
    ctx.close()
    ctx.close()
    assert ctx.stop_event.is_set()
    ctx.task_pool.close.assert_called_once_with(deadline=310)
    ctx.ingest_pool.close.assert_called_once_with(deadline=310)
    ctx.worker_manager.shutdown.assert_called_once()
    ctx.health_monitor.close.assert_called_once()
    cleanup.assert_called_once_with()


def test_context_shutdown_continues_after_pool_and_manager_errors():
    ctx = make_context()
    ctx.stop_event = Event()
    ctx.task_pool = Mock()
    ctx.task_pool.close.side_effect = RuntimeError("pool failed")
    ctx.ingest_pool = Mock()
    ctx.worker_manager = Mock()
    ctx.worker_manager.shutdown.side_effect = RuntimeError("manager failed")
    ctx.task_queue.cancel_join_thread = Mock(side_effect=RuntimeError("feeder failed"))
    ctx.close()
    ctx.ingest_pool.close.assert_called_once()
    assert ctx.task_queue.closed
    assert ctx.dir_busting_result_queue.closed


@pytest.mark.asyncio
async def test_get_server_context_returns_cached_context(monkeypatch):
    ctx = make_context()
    monkeypatch.setattr(server_context, "_server_context", ctx)

    assert await server_context.get_server_context() is ctx


def test_close_server_context_closes_and_clears_global(monkeypatch):
    ctx = make_context()
    monkeypatch.setattr(server_context, "_server_context", ctx)

    close_server_context()

    assert ctx.task_pool.closed is True
    assert server_context._server_context is None


@pytest.mark.asyncio
async def test_server_context_ensure_retrieval_pipelines(monkeypatch):
    ctx = make_context()
    doc_pipeline = object()
    ctx_pipeline = object()
    stores = {"retriever": object()}

    monkeypatch.setattr(server_context, "get_generator_config", lambda: "gen_config")

    async def mock_build_doc_pipe(db, generator_config):
        assert db == "db"
        assert generator_config == "gen_config"
        return doc_pipeline, None, stores

    monkeypatch.setattr(server_context, "build_document_pipeline", mock_build_doc_pipe)
    monkeypatch.setattr(server_context, "build_website_context_pipeline", lambda generator_config: ctx_pipeline)

    assert ctx.document_pipeline is None
    assert ctx.website_context_pipeline is None

    await ctx.ensure_retrieval_pipelines()

    assert ctx.document_pipeline is doc_pipeline
    assert ctx.website_context_pipeline is ctx_pipeline
    assert ctx.stores == stores

    # Second call should not re-run pipeline builders
    monkeypatch.setattr(server_context, "build_document_pipeline", lambda *args, **kwargs: pytest.fail("Should not build again"))
    await ctx.ensure_retrieval_pipelines()


def test_server_context_low_power_toggle_controls_indexing_event():
    event = server_context.multiprocessing.Event()
    event.set()
    ctx = make_context()
    ctx.indexing_enabled = event

    ctx.set_low_power(True)
    assert ctx.low_power is True
    assert not event.is_set()

    ctx.set_low_power(False)
    assert ctx.low_power is False
    assert event.is_set()


def test_server_context_low_power_toggle_without_indexing_event():
    ctx = make_context()

    ctx.set_low_power(True)

    assert ctx.low_power is True


@pytest.mark.asyncio
async def test_enqueue_ingest_uses_durable_writer_and_closes_it(monkeypatch):
    from unittest.mock import AsyncMock

    writer = Mock(put=AsyncMock())
    factory = Mock(return_value=writer)
    monkeypatch.setattr(server_context, "AsyncIngestWriter", factory)
    ctx = make_context()
    ctx.ingest_queue.path = "/tmp/queue"
    await ctx.enqueue_ingest("first")
    await ctx.enqueue_ingest("second")
    factory.assert_called_once_with("/tmp/queue")
    assert [call.args for call in writer.put.await_args_list] == [("first",), ("second",)]
    ctx.close()
    writer.close.assert_called_once()
    assert 0 < writer.close.call_args.kwargs["timeout"] <= 300
    with pytest.raises(RuntimeError, match="shutting down"):
        await ctx.enqueue_ingest("rejected")


def test_writer_close_failure_does_not_skip_other_shutdown(caplog):
    ctx = make_context()
    ctx._ingest_writer = Mock()
    ctx._ingest_writer.close.side_effect = RuntimeError("writer failed")
    ctx.close()
    assert ctx.ingest_pool.closed
    assert ctx.ingest_queue.closed
    assert "Failed to close ingest writer" in caplog.text
