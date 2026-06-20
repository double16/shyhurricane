import pytest

import shyhurricane.mcp_server.server_context as server_context
from shyhurricane.mcp_server.server_context import ServerContext, close_server_context


class Closeable:
    def __init__(self, fail=False):
        self.fail = fail
        self.closed = False
        self.items = []

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
    assert ctx.ingest_queue.items == [None]
    assert ctx.task_queue.items == [None]
    assert ctx.spider_result_queue.items == [None]
    assert ctx.port_scan_result_queue.items == [None]
    assert ctx.ingest_queue.closed is True


def test_server_context_close_swallows_queue_errors():
    ctx = make_context(failing_queue=True)

    ctx.close()

    assert ctx.task_pool.closed is True
    assert ctx.ingest_pool.closed is True


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
