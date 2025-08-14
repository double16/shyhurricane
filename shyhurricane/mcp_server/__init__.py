import asyncio
import ipaddress
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, AsyncIterator, Any, Annotated, Optional, TypeAlias

import aiofiles
import validators
from mcp import McpError, ErrorData
from mcp.server import FastMCP
from mcp.server.fastmcp import Context
from mcp.types import INVALID_REQUEST, Tool
from pydantic import ValidationError, Field

import shyhurricane.mcp_server.server_context
from shyhurricane.mcp_server.app_context import AppContext
from shyhurricane.server_config import get_server_config
from shyhurricane.mcp_server.server_context import get_server_context, ServerContext
from shyhurricane.oast.interactsh import InteractProvider
from shyhurricane.oast.webhook_site import WebhookSiteProvider
from shyhurricane.prompts import mcp_server_instructions
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)

AdditionalHostsField: TypeAlias = Annotated[
    Optional[Dict[str, str]],
    Field(
        None,
        description=(
            "The additional_hosts parameter is a dictionary of host name (the key) "
            "to IP address (the value) for hosts that do not have DNS records. "
            "This also includes CTF targets or web server virtual hosts found during "
            "other scans. If you know the IP address for a host, be sure to include "
            "these in the additional_hosts parameter for commands to run properly "
            "in a containerized environment."
        )
    )
]

ProcessEnvField: TypeAlias = Annotated[Optional[Dict[str, str]], Field(
    None,
    description="Environment variables to set for the process."
)]


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle (per session) with type-safe context"""
    _server_config = get_server_config()
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

    if _server_config.oast.provider == "interactsh":
        oast_provider = InteractProvider()
    else:
        oast_provider = WebhookSiteProvider()

    app_context = AppContext(
        cache_path=cache_path,
        app_context_id=app_context_id,
        work_path=work_path,
        cached_get_additional_hosts={},
        oast_provider=oast_provider,
    )

    try:
        yield app_context
    finally:
        # Cleanup on shutdown
        if oast_provider.inited:
            await oast_provider.deregister()
        await app_context.channel_manager.cleanup()


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
    data["timestamp"] = datetime.now().isoformat()
    data_str = json.dumps(data)
    try:
        if ctx is None:
            logger.info(data_str)
        else:
            async with aiofiles.open(os.path.join(ctx.request_context.lifespan_context.cache_path, 'history.jsonl'),
                                     'ta') as history_file:
                await history_file.write(data_str)
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
