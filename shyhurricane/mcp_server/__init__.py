import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, AsyncIterator, Any

import aiofiles
import validators
from mcp import McpError, ErrorData
from mcp.server import FastMCP
from mcp.server.fastmcp import Context
from mcp.types import INVALID_REQUEST, Tool
from pydantic import ValidationError

import shyhurricane.mcp_server.server_context
from shyhurricane.mcp_server.server_context import get_server_context, ServerContext
from shyhurricane.prompts import mcp_server_instructions
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    # TODO: add scope?
    cached_get_additional_hosts: Dict[str, str]
    cache_path: str
    app_context_id: str
    work_path: str

    def get_cache_path_for_tool(self, tool_id_str: str, additional_hosts: Dict[str, str]) -> str:
        digest = hashlib.sha512()
        digest.update(tool_id_str.encode("utf-8"))
        if additional_hosts:
            digest.update(json.dumps(additional_hosts).encode("utf-8"))
        sha512_str = digest.hexdigest()
        path = os.path.join(self.cache_path, sha512_str[0:2], sha512_str[2:4], sha512_str[4:])
        os.makedirs(path, exist_ok=True)
        return path


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle (per session) with type-safe context"""
    # Initialize on startup
    server_ctx = await get_server_context()
    cache_path = server_ctx.cache_path

    app_context_id = uuid.uuid4().hex

    work_path = f"/work/{app_context_id}"
    proc = await asyncio.create_subprocess_exec("docker", "run", "--rm",
                                                "-v", f"{server_ctx.mcp_session_volume}:/work",
                                                unix_command_image(),
                                                "mkdir", "-p", work_path,
                                                stdout=asyncio.subprocess.DEVNULL,
                                                stderr=asyncio.subprocess.DEVNULL,
                                                )
    return_code = await proc.wait()
    if return_code != 0:
        logger.error("Failed to create MCP session work dir %s", work_path)
        work_path = "/var/tmp"

    try:
        yield AppContext(
            cache_path=cache_path,
            app_context_id=app_context_id,
            work_path=work_path,
            cached_get_additional_hosts={},
        )
    finally:
        # Cleanup on shutdown
        pass


class ShyHurricaneFastMCP(FastMCP):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_world = True

    async def list_tools(self) -> list[Tool]:
        logger.info("Listing tools")
        tools = await super().list_tools()
        if not self.open_world:
            logger.info("Filtering tools for open_world = False")
            tools = list(
                filter(lambda tool: tool.annotations is not None and tool.annotations.openWorldHint == False, tools))
        return tools


mcp_instance = ShyHurricaneFastMCP("shyhurricane", lifespan=app_lifespan, instructions=mcp_server_instructions)


def assert_elicitation(ctx: ServerContext):
    if ctx.disable_elicitation:
        raise McpError(ErrorData(code=INVALID_REQUEST, message="elicitation disabled"))


async def log_history(ctx: Context, data: Dict[str, Any]):
    try:
        async with aiofiles.open(os.path.join(ctx.request_context.lifespan_context.cache_path, 'history.jsonl'),
                                 'ta') as history_file:
            data["timestamp"] = datetime.now().isoformat()
            await history_file.write(json.dumps(data))
            await history_file.write("\n")
    except IOError as e:
        logger.info("Cannot write to history file", exc_info=e)


async def log_tool_history(ctx: Context, title: str, **kwargs):
    data = {
        "tool": title,
        "arguments": kwargs or {},
    }
    await log_history(ctx, data)
    logger.info(f"{title}: {json.dumps(data)}")


def get_additional_hosts(ctx: Context, additional_hosts: Dict[str, str] = None) -> Dict[str, str]:
    cached_get_additional_hosts = ctx.request_context.lifespan_context.cached_get_additional_hosts
    if not additional_hosts:
        return cached_get_additional_hosts
    validated: Dict[str, str] = {}
    for host, ip in (additional_hosts or {}).items():
        try:
            if validators.domain(host) == True and ipaddress.ip_address(ip):
                validated[host] = ip
                cached_get_additional_hosts[host] = ip
        except (ValueError, ValidationError):
            pass
    return cached_get_additional_hosts | validated
