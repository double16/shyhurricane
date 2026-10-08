"""Keep client configuration separate from the SDK's shared server lifespan."""

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace

import anyio
from mcp import MCPError
from mcp.server.connection import Connection
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import INVALID_PARAMS, ListToolsResult
from mcp.types.version import MODERN_PROTOCOL_VERSIONS

from shyhurricane.mcp_server.app_context import AppContext
from shyhurricane.mcp_server.progress import progress_scope
from shyhurricane.mcp_server.server_context import ServerContext, get_server_context
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)
REGISTRATION_TOOLS = {"register_http_headers", "register_hostname_address"}
_STATE_KEY = "shyhurricane.app_context"
_LOCK_KEY = "shyhurricane.app_context_lock"


def get_connection(ctx: ServerRequestContext) -> Connection:
    """Bridge MCP 2.2's request proxy to its connection lifecycle in one place.

    The high-level request context has no public connection accessor in MCP 2.2.
    Keep this version-specific access here until the SDK exposes one.
    """
    return ctx.session._connection


@dataclass
class ClientAppContext(AppContext):
    volume: str
    _work_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _work_started: bool = False
    _work_ready: bool = False

    async def ensure_work_path(self) -> str:
        async with self._work_lock:
            if not self._work_ready:
                self._work_started = True
                proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{self.volume}:/work",
                    unix_command_image(),
                    "mkdir",
                    "-p",
                    self.work_path,
                    f"{self.work_path}/.private/tmp",
                    f"{self.work_path}/.private/var/tmp",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                if await proc.wait() != 0:
                    raise ToolError("Failed to create MCP working directory")
                self._work_ready = True
        return self.work_path

    async def close(self) -> None:
        if self._work_started:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "run",
                "--rm",
                "-v",
                f"{self.volume}:/work",
                unix_command_image(),
                "rm",
                "-rf",
                self.work_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await proc.wait() != 0:
                logger.warning("Failed to remove MCP working directory %s", self.work_path)
            self._work_started = False
            self._work_ready = False


async def create_client_context() -> ClientAppContext:
    server_ctx = await get_server_context()
    context_id = uuid.uuid4().hex
    return ClientAppContext(
        cached_get_additional_hosts={},
        http_headers={},
        cache_path=server_ctx.cache_path,
        app_context_id=context_id,
        work_path=f"/work/{context_id}",
        volume=server_ctx.mcp_session_volume,
    )


@asynccontextmanager
async def app_lifespan(server: MCPServer) -> AsyncIterator[ServerContext]:
    """Initialize shared services without allocating client state or directories."""
    yield await get_server_context()


async def ensure_work_path(ctx: Context) -> str:
    state = ctx.request_context.lifespan_context
    if isinstance(state, ClientAppContext):
        return await state.ensure_work_path()
    # Helpers may be invoked directly with an already provisioned context.
    return state.work_path


@progress_scope(fresh=True)
async def client_state_middleware(ctx: ServerRequestContext, call_next: CallNext) -> HandlerResult:
    connection = get_connection(ctx)
    request_local = ctx.protocol_version in MODERN_PROTOCOL_VERSIONS or not ctx.session.can_send_request
    if request_local and ctx.method == "tools/call" and (ctx.params or {}).get("name") in REGISTRATION_TOOLS:
        raise MCPError(
            INVALID_PARAMS,
            "Registration requires a legacy session. Supply request_headers and additional_hosts on each operation.",
        )
    if ctx.method != "tools/call":
        result = await call_next(ctx)
        if request_local and ctx.method == "tools/list" and isinstance(result, ListToolsResult):
            result = result.model_copy(
                update={
                    "tools": [tool for tool in result.tools if tool.name not in REGISTRATION_TOOLS],
                }
            )
        elif request_local and ctx.method == "tools/list" and isinstance(result, dict):
            result = {
                **result,
                "tools": [tool for tool in result.get("tools", []) if tool["name"] not in REGISTRATION_TOOLS],
            }
        return result

    if request_local:
        state = await create_client_context()
        try:
            return await call_next(replace(ctx, lifespan_context=state))
        finally:
            with anyio.CancelScope(shield=True):
                await state.close()

    # Every connection gets one lock, installed before the first await.
    lock = connection.state.setdefault(_LOCK_KEY, asyncio.Lock())
    async with lock:
        if _STATE_KEY not in connection.state:
            state = await create_client_context()
            connection.state[_STATE_KEY] = state
            connection.exit_stack.push_async_callback(state.close)
        state = connection.state[_STATE_KEY]
    return await call_next(replace(ctx, lifespan_context=state))
