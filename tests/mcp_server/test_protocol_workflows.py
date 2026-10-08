import asyncio
import socket
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx2
import pytest
import uvicorn
from mcp import Client, MCPError
from mcp.client.sse import sse_client
from mcp.server.mcpserver import Context
from mcp.types import ElicitResult, InputRequiredResult
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

import mcp_service
from shyhurricane.mcp_server import ShyHurricaneMCPServer, session_state
from shyhurricane.mcp_server.tools import find_web_resources as resources
from shyhurricane.mcp_server.tools.register_hostname_address import register_hostname_address
from shyhurricane.mcp_server.tools.register_http_headers import register_http_headers


class Pipeline:
    async def run_async(self, data, **kwargs):
        return self.run(data, **kwargs)

    def run(self, data, **kwargs):
        if "builder" in data:
            query = data["builder"]["query"]
            target = '["missing.example.com"]' if "missing.example.com" in query else "[]"
            return {"llm": {"replies": [f'{{"target": {target}}}']}}
        return {"combine": {"documents": []}}


@pytest.fixture
def workflow_server(monkeypatch, tmp_path):
    context = SimpleNamespace(
        cache_path=str(tmp_path),
        mcp_session_volume="test-volume",
        disable_elicitation=False,
        open_world=True,
        low_power=False,
        website_context_pipeline=Pipeline(),
        document_pipeline=Pipeline(),
    )
    monkeypatch.setattr(session_state, "get_server_context", AsyncMock(return_value=context))
    monkeypatch.setattr(resources, "get_server_context", AsyncMock(return_value=context))
    for helper in ["_find_web_resources_by_url", "_find_web_resources_by_netloc", "_find_web_resources_by_hostname"]:
        monkeypatch.setattr(resources, helper, AsyncMock(return_value=None))
    monkeypatch.setattr(resources, "_find_recommended_urls", AsyncMock(return_value=[]))
    monkeypatch.setattr(resources, "find_netloc", AsyncMock(return_value=SimpleNamespace(network_locations=[])))
    monkeypatch.setattr(resources, "log_tool_history", AsyncMock())
    monkeypatch.setattr(resources, "spider_website", AsyncMock())

    @asynccontextmanager
    async def lifespan(server):
        yield context

    server = ShyHurricaneMCPServer(
        "workflow-test", lifespan=lifespan, middleware=[session_state.client_state_middleware]
    )
    server.add_tool(resources.find_web_resources_tool, name="find_web_resources")
    server.add_tool(register_http_headers)
    server.add_tool(register_hostname_address)

    @server.tool()
    async def probe(ctx: Context) -> dict[str, Any]:
        state = ctx.request_context.lifespan_context
        return {"id": state.app_context_id, "headers": state.http_headers, "hosts": state.cached_get_additional_hosts}

    return server, context


@pytest.mark.asyncio
async def test_real_legacy_clients_preserve_and_isolate_registration(workflow_server):
    server, _ = workflow_server
    async with Client(server, mode="legacy") as first, Client(server, mode="legacy") as second:
        await first.call_tool("register_http_headers", {"http_headers": {"X-Test": "one"}})
        await first.call_tool("register_hostname_address", {"host": "example.com", "address": "127.0.0.1"})
        a = (await first.call_tool("probe")).structured_content
        b = (await first.call_tool("probe")).structured_content
        c = (await second.call_tool("probe")).structured_content
        assert a == b
        assert a["id"] != c["id"]
        assert a["headers"] == {"X-Test": "one"}
        assert a["hosts"] == {"example.com": "127.0.0.1"}
        assert c["headers"] == c["hosts"] == {}


@pytest.mark.asyncio
async def test_real_modern_client_has_fresh_state_and_no_registration(workflow_server):
    server, _ = workflow_server
    async with Client(server) as client:
        names = [tool.name for tool in (await client.list_tools()).tools]
        assert "register_http_headers" not in names
        assert "register_hostname_address" not in names
        a = (await client.call_tool("probe")).structured_content
        b = (await client.call_tool("probe")).structured_content
        assert a["id"] != b["id"]
        for name, arguments in [
            ("register_http_headers", {"http_headers": {"X-Test": "one"}}),
            ("register_hostname_address", {"host": "example.com", "address": "127.0.0.1"}),
        ]:
            with pytest.raises(MCPError, match="Registration requires"):
                await client.call_tool(name, arguments)


@pytest.mark.asyncio
@pytest.mark.filterwarnings("error::mcp.shared.exceptions.MCPDeprecationWarning")
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("with_progress", [True, False])
async def test_search_progress_without_deprecated_logging(workflow_server, mode, with_progress):
    server, _ = workflow_server
    updates = []

    async def progress(value, total, message):
        updates.append((value, total, message))

    async def answer(ctx, params):
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(server, mode=mode, elicitation_callback=answer) as client:
        result = await client.call_tool(
            "find_web_resources",
            {"query": "missing.example.com"},
            progress_callback=progress if with_progress else None,
        )
    assert not result.is_error
    expected = [(1, None, "Determining target(s)"), (2, None, "Searching for missing.example.com")]
    if mode != "legacy":
        # Modern elicitation resumes in a new inbound request and prepares the search again.
        expected.insert(0, (1, None, "Determining target(s)"))
    assert updates == (expected if with_progress else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "modern"])
@pytest.mark.parametrize(
    "action,confirm,scans", [("accept", True, 2), ("accept", False, 0), ("decline", None, 0), ("cancel", None, 0)]
)
async def test_legacy_and_modern_scan_confirmation(workflow_server, mode, action, confirm, scans):
    server, _ = workflow_server
    questions = []

    async def answer(ctx, params):
        questions.append(params.message)
        assert resources.spider_website.await_count == 0
        return ElicitResult(action=action, content={"confirm": confirm} if action == "accept" else None)

    async with Client(server, mode="2026-07-28" if mode == "modern" else mode, elicitation_callback=answer) as client:
        result = await client.call_tool("find_web_resources", {"query": "missing.example.com"})
        assert not result.is_error
        assert len(questions) == 1
        assert resources.spider_website.await_count == scans


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "modern"])
async def test_two_questions_resolve_before_any_scanning(workflow_server, mode):
    server, _ = workflow_server
    questions = []

    async def answer(ctx, params):
        questions.append(params.message)
        assert resources.spider_website.await_count == 0
        return ElicitResult(
            action="accept", content={"data": "missing.example.com"} if len(questions) == 1 else {"confirm": True}
        )

    async with Client(server, mode="2026-07-28" if mode == "modern" else mode, elicitation_callback=answer) as client:
        tools = (await client.list_tools()).tools
        tool = next(tool for tool in tools if tool.name == "find_web_resources")
        assert set(tool.input_schema["properties"]) == {"query", "limit", "http_methods"}
        result = await client.call_tool("find_web_resources", {"query": "find vulnerabilities"})
        assert not result.is_error
        assert len(questions) == 2
        assert resources.spider_website.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "modern"])
@pytest.mark.parametrize("disabled", [True, False])
async def test_disabled_or_unsupported_elicitation_never_scans(workflow_server, mode, disabled):
    server, context = workflow_server
    context.disable_elicitation = disabled
    async with Client(server, mode="2026-07-28" if mode == "modern" else mode) as client:
        for query in ["find vulnerabilities", "missing.example.com"]:
            result = await client.call_tool("find_web_resources", {"query": query})
            assert not result.is_error
        resources.spider_website.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("action,scans", [("accept", 1), ("decline", 0)])
async def test_predicate_missing_site_uses_scan_confirmation(workflow_server, mode, action, scans):
    server, context = workflow_server
    context.low_power = True
    questions = []

    async def answer(ctx, params):
        questions.append(params.message)
        return ElicitResult(action=action, content={"confirm": True} if action == "accept" else None)

    async with Client(server, mode=mode, elicitation_callback=answer) as client:
        result = await client.call_tool("find_web_resources", {"query": "site:missing.example.com ext:js"})
        assert not result.is_error
        assert result.structured_content["resources"] == []
    assert len(questions) == 1
    assert resources.spider_website.await_count == scans


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_predicate_only_mcp_search_bypasses_llm_and_preserves_schema(workflow_server, mode, monkeypatch):
    server, context = workflow_server
    context.low_power = True
    context.website_context_pipeline = context.document_pipeline = None
    context.qdrant_client = SimpleNamespace(get_collections=AsyncMock(return_value=SimpleNamespace(collections=[])))
    monkeypatch.setattr(resources, "find_netloc", AsyncMock(return_value=SimpleNamespace(
        network_locations=["example.com:443"],
    )))
    async with Client(server, mode=mode) as client:
        tool = next(tool for tool in (await client.list_tools()).tools if tool.name == "find_web_resources")
        assert set(tool.input_schema["properties"]) == {"query", "limit", "http_methods"}
        result = await client.call_tool("find_web_resources", {"query": "site:example.com status:200"})
        assert not result.is_error
        assert result.structured_content["query"] == "site:example.com status:200"
        assert result.structured_content["resources"] == []
        invalid = await client.call_tool("find_web_resources", {"query": "site:example.com status:wrong"})
        assert invalid.is_error
        assert "status:" in str(invalid.content)
    resources.spider_website.assert_not_awaited()


@pytest.mark.asyncio
async def test_modern_continuation_is_protected_and_bound_to_arguments(workflow_server):
    server, _ = workflow_server

    async def answer(ctx, params):
        return ElicitResult(action="decline")

    async with Client(server, elicitation_callback=answer) as client:
        result = await client.session.call_tool(
            "find_web_resources",
            {"query": "missing.example.com"},
            allow_input_required=True,
        )
        assert isinstance(result, InputRequiredResult)
        assert result.request_state
        for token, query in [("invalid", "missing.example.com"), (result.request_state, "different.example.com")]:
            with pytest.raises(MCPError, match="Invalid or expired requestState"):
                await client.session.call_tool(
                    "find_web_resources",
                    {"query": query},
                    request_state=token,
                    allow_input_required=True,
                )
        resources.spider_website.assert_not_awaited()


@pytest.fixture
async def http_endpoint(workflow_server, monkeypatch, request):
    server, _ = workflow_server

    @server.custom_route("/status", methods=["POST"])
    async def status(request):
        return JSONResponse({"healthy": True})

    monkeypatch.setattr(mcp_service, "mcp_instance", server)
    app = mcp_service.build_mcp_app(request.param, "127.0.0.1")
    app = CORSMiddleware(
        app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id"],
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    address = f"http://127.0.0.1:{sock.getsockname()[1]}"
    runner = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
    task = asyncio.create_task(runner.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(5):
            while not runner.started:
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)
        yield address
    finally:
        runner.should_exit = True
        await task
        sock.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("http_endpoint", mcp_service.TRANSPORTS, indirect=True)
async def test_http_transports_custom_routes_and_cors(http_endpoint, request):
    transport = request.node.callspec.params["http_endpoint"]
    if transport == "sse":
        target = sse_client(f"{http_endpoint}/sse")
        mode = "legacy"
    else:
        target = f"{http_endpoint}/mcp"
        mode = "legacy" if transport == "streamable-http" else "2026-07-28"
    async with Client(target, mode=mode) as client:
        assert "probe" in [tool.name for tool in (await client.list_tools()).tools]
        result = await client.call_tool("probe")
        assert result.structured_content["headers"] == {}
        if mode == "legacy":
            await client.call_tool("register_http_headers", {"http_headers": {"X-Test": "http"}})
            assert (await client.call_tool("probe")).structured_content["headers"] == {"X-Test": "http"}
    if transport != "sse":
        async with Client(f"{http_endpoint}/mcp") as modern:
            assert modern.protocol_version == "2026-07-28"
            names = [tool.name for tool in (await modern.list_tools()).tools]
            assert "register_http_headers" not in names
            a = (await modern.call_tool("probe")).structured_content
            b = (await modern.call_tool("probe")).structured_content
            assert a["id"] != b["id"]
            assert a["headers"] == b["headers"] == {}
    if transport == "streamable-http-modern":
        callback = AsyncMock(return_value=ElicitResult(action="accept", content={"confirm": True}))
        async with Client(f"{http_endpoint}/mcp", mode="legacy", elicitation_callback=callback) as legacy:
            result = await legacy.call_tool("find_web_resources", {"query": "missing.example.com"})
            assert not result.is_error
            callback.assert_not_awaited()
            resources.spider_website.assert_not_awaited()
    async with httpx2.AsyncClient() as http:
        response = await http.post(f"{http_endpoint}/status", headers={"Origin": "https://example.com"})
        assert response.json() == {"healthy": True}
        assert response.headers["access-control-allow-origin"] == "*"
        preflight = await http.options(
            f"{http_endpoint}/status",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "MCP-Protocol-Version",
            },
        )
        assert preflight.status_code == 200
        if transport != "sse":
            too_large = await http.post(
                f"{http_endpoint}/mcp",
                content=b"x" * (4 * 1024 * 1024 + 1),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            assert too_large.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("with_progress", [True, False])
@pytest.mark.parametrize("tool_name", [
    "spider_website", "directory_buster", "port_scan", "find_web_resources",
    "deobfuscate_javascript", "index_http_url", "find_wordlists",
])
async def test_idle_progress_through_middleware(workflow_server, monkeypatch, mode, with_progress, tool_name):
    from shyhurricane.mcp_server import progress

    server, _ = workflow_server
    monkeypatch.setattr(progress, "PROGRESS_INTERVAL_SECONDS", 0.01)
    updates = []

    async def receive(value, total, message):
        updates.append((value, total, message))

    @progress.progress_scope()
    async def nested(ctx):
        await asyncio.sleep(0.035)
        await progress.report_progress(ctx, "Useful update")
        await asyncio.sleep(0.035)

    async def silent_tool(ctx: Context) -> str:
        await nested(ctx)
        return "done"

    if tool_name == "find_web_resources":
        server.remove_tool(tool_name)
    server.add_tool(silent_tool, name=tool_name)
    async with Client(server, mode=mode) as client:
        result = await client.call_tool(tool_name, progress_callback=receive if with_progress else None)
        assert not result.is_error
        count_after_return = len(updates)
        await asyncio.sleep(0.025)
        assert len(updates) == count_after_return
    if not with_progress:
        assert updates == []
    elif tool_name == "find_wordlists":
        assert updates == [(1, None, "Useful update")]
    else:
        assert len(updates) >= 3
        assert [value for value, _, _ in updates] == list(range(1, len(updates) + 1))
        assert all(total is None for _, total, _ in updates)
        assert any(message == f"{tool_name} is still running" for _, _, message in updates)
