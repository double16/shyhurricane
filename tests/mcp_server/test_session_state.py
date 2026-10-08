import asyncio
from contextlib import AsyncExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp import MCPError
from mcp.server import ServerRequestContext
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ListToolsResult, Tool

from shyhurricane.mcp_server import session_state as state


@pytest.fixture
def server_context(monkeypatch, tmp_path):
    context = SimpleNamespace(cache_path=str(tmp_path), mcp_session_volume="test-volume")
    monkeypatch.setattr(state, "get_server_context", AsyncMock(return_value=context))
    return context


def request(connection, method="tools/call", name="probe", modern=False, can_send=True):
    return ServerRequestContext(
        session=SimpleNamespace(_connection=connection, can_send_request=can_send),
        lifespan_context=object(),
        protocol_version="2026-07-28" if modern else "2025-11-25",
        method=method,
        params={"name": name},
        request_id="test",
    )


def connection():
    return SimpleNamespace(state={}, exit_stack=AsyncExitStack())


@pytest.mark.asyncio
async def test_shared_lifespan_does_not_allocate_client_work(server_context, monkeypatch):
    create = AsyncMock()
    monkeypatch.setattr(state.asyncio, "create_subprocess_exec", create)
    async with state.app_lifespan(object()) as context:
        assert context is server_context
    create.assert_not_called()


@pytest.mark.asyncio
async def test_legacy_state_is_reused_and_other_connections_are_isolated(server_context):
    first, second = connection(), connection()

    async def mutate(ctx):
        context = ctx.lifespan_context
        context.http_headers["X-Test"] = "yes"
        return context

    a, b = await asyncio.gather(
        state.client_state_middleware(request(first), mutate),
        state.client_state_middleware(request(first), mutate),
    )
    c = await state.client_state_middleware(request(second), mutate)
    assert a is b
    assert c is not a
    assert a.work_path != c.work_path
    assert a.http_headers is not c.http_headers
    await first.exit_stack.aclose()
    await second.exit_stack.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("modern,can_send", [(True, False), (False, False)])
async def test_request_local_state_is_fresh(server_context, modern, can_send):
    conn = connection()

    async def mutate(ctx):
        context = ctx.lifespan_context
        assert context.http_headers == {}
        context.http_headers["X-Test"] = "yes"
        return context

    a = await state.client_state_middleware(request(conn, modern=modern, can_send=can_send), mutate)
    b = await state.client_state_middleware(request(conn, modern=modern, can_send=can_send), mutate)
    assert a is not b
    assert conn.state == {}


@pytest.mark.asyncio
async def test_modern_listing_filters_registrations_and_direct_calls_are_rejected(server_context):
    conn = connection()
    tools = [Tool(name=name, input_schema={}) for name in [*sorted(state.REGISTRATION_TOOLS), "probe"]]
    listing = AsyncMock(return_value=ListToolsResult(tools=tools))
    result = await state.client_state_middleware(request(conn, method="tools/list", modern=True), listing)
    assert [tool.name for tool in result.tools] == ["probe"]
    assert len(tools) == 3
    for name in state.REGISTRATION_TOOLS:
        with pytest.raises(MCPError, match="Supply request_headers and additional_hosts"):
            await state.client_state_middleware(request(conn, name=name, modern=True), listing)

    # Other methods and non-model middleware results pass through unchanged.
    sentinel = object()
    for method, modern in [("ping", True), ("tools/list", True), ("tools/list", False)]:
        assert (
            await state.client_state_middleware(
                request(conn, method=method, modern=modern),
                AsyncMock(return_value=sentinel),
            )
            is sentinel
        )


@pytest.mark.asyncio
async def test_work_path_is_lazy_created_once_and_cleanup_is_awaited(server_context, monkeypatch):
    commands = []

    async def subprocess(*args, **kwargs):
        proc = SimpleNamespace(wait=AsyncMock(return_value=0))
        commands.append((args, proc))
        return proc

    monkeypatch.setattr(state.asyncio, "create_subprocess_exec", subprocess)
    context = await state.create_client_context()
    assert not commands
    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))
    paths = await asyncio.gather(state.ensure_work_path(ctx), state.ensure_work_path(ctx))
    assert paths == [context.work_path, context.work_path]
    assert len(commands) == 1
    await context.close()
    await context.close()
    assert len(commands) == 2
    assert commands[1][0][-3:] == ("rm", "-rf", context.work_path)
    assert all(proc.wait.await_count == 1 for _, proc in commands)
    assert (
        await state.ensure_work_path(
            SimpleNamespace(request_context=SimpleNamespace(lifespan_context=SimpleNamespace(work_path="/existing"))),
        )
        == "/existing"
    )


@pytest.mark.asyncio
async def test_work_path_failure_does_not_fall_back_to_shared_directory(server_context, monkeypatch, caplog):
    monkeypatch.setattr(
        state.asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=SimpleNamespace(wait=AsyncMock(return_value=1))),
    )
    context = await state.create_client_context()
    with pytest.raises(ToolError, match="Failed to create"):
        await context.ensure_work_path()
    assert context.work_path.startswith("/work/")
    await context.close()
    assert "Failed to remove" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
async def test_modern_cleanup_runs_after_failure_or_cancellation(server_context, monkeypatch, failure):
    close = AsyncMock()
    monkeypatch.setattr(state.ClientAppContext, "close", close)

    async def fail(ctx):
        raise failure()

    with pytest.raises(failure):
        await state.client_state_middleware(request(connection(), modern=True), fail)
    close.assert_awaited_once()
