import unittest

from mcp.server.fastmcp import Context
from mcp.shared.context import RequestContext

from unittest.mock import patch, AsyncMock, Mock

from shyhurricane.mcp_server.tools.register_http_headers import register_http_headers


class TestRegisterHttpHeaders(unittest.IsolatedAsyncioTestCase):

    def new_context(self) -> Context:
        server_context = Mock(spec=["cache_path", "work_path", "cached_get_additional_hosts", "http_headers"])
        server_context.cache_path = "/var/tmp"
        server_context.work_path = "/var/tmp"
        server_context.cached_get_additional_hosts = {}
        server_context.http_headers = {}
        return Context(request_context=RequestContext(
            request_id="unittest",
            meta=None,
            session=Mock(),
            lifespan_context=server_context
        ))

    @patch("shyhurricane.mcp_server.log_tool_history", new_callable=AsyncMock)
    async def test_register_http_header(self, mock_log):
        ctx = self.new_context()
        await register_http_headers(ctx, {"X-Header1": "Value1"})
        assert ctx.request_context.lifespan_context.http_headers["X-Header1"] == "Value1"
        await register_http_headers(ctx, {"X-Header2": "Value2"})
        assert ctx.request_context.lifespan_context.http_headers["X-Header1"] == "Value1"
        assert ctx.request_context.lifespan_context.http_headers["X-Header2"] == "Value2"
