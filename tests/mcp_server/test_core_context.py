import pytest
from mcp import McpError

import shyhurricane.mcp_server as mcp_server
from shyhurricane.mcp_server.server_context import ServerContext


class LifespanContext:
    def __init__(self, tmp_path):
        self.cached_get_additional_hosts = {}
        self.http_headers = {"X-Global": "yes"}
        self.cache_path = str(tmp_path)


class RequestContext:
    def __init__(self, tmp_path):
        self.lifespan_context = LifespanContext(tmp_path)


class Ctx:
    def __init__(self, tmp_path):
        self.request_context = RequestContext(tmp_path)


def test_assert_elicitation_raises_when_disabled():
    ctx = ServerContext(
        db="db",
        cache_path="/tmp",
        document_pipeline=None,
        website_context_pipeline=None,
        ingest_queue=None,
        ingest_pool=None,
        task_queue=None,
        task_pool=None,
        spider_result_queue=None,
        port_scan_result_queue=None,
        dir_busting_result_queue=None,
        stores={},
        qdrant_client=None,
        mcp_session_volume="volume",
        disable_elicitation=True,
    )

    with pytest.raises(McpError):
        mcp_server.assert_elicitation(ctx)


def test_get_additional_hosts_validates_and_caches(tmp_path):
    ctx = Ctx(tmp_path)

    result = mcp_server.get_additional_hosts(
        ctx,
        {"example.com": "127.0.0.1", "bad host": "127.0.0.2", "other.test": "not-ip"},
    )

    assert result == {"example.com": "127.0.0.1"}
    assert mcp_server.get_additional_hosts(ctx) == {"example.com": "127.0.0.1"}


def test_get_additional_http_headers_merges_cached_and_supplied(tmp_path):
    ctx = Ctx(tmp_path)

    assert mcp_server.get_additional_http_headers(ctx, {"X-Local": "ok"}) == {
        "X-Global": "yes",
        "X-Local": "ok",
    }


@pytest.mark.asyncio
async def test_log_history_writes_jsonl_and_handles_none_context(tmp_path):
    ctx = Ctx(tmp_path)

    await mcp_server.log_history(ctx, {"event": "test"})
    await mcp_server.log_tool_history(ctx, "tool", arg=1)
    await mcp_server.log_history(None, {"event": object()})

    lines = (tmp_path / "history.jsonl").read_text().splitlines()
    assert '"event": "test"' in lines[0]
    assert '"tool": "tool"' in lines[1]
