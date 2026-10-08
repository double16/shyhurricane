import ipaddress
import json
import logging
import os
from datetime import datetime
from typing import Annotated, Any, Dict, Optional, TypeAlias, Union

import aiofiles
import validators
from mcp import MCPError
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import INVALID_REQUEST, Tool
from pydantic import Field, ValidationError

from shyhurricane.mcp_server.server_context import ServerContext
from shyhurricane.mcp_server.server_context import get_server_context as get_server_context
from shyhurricane.mcp_server.session_state import app_lifespan, client_state_middleware

logger = logging.getLogger(__name__)

AdditionalHostsField: TypeAlias = Annotated[
    Optional[Union[Dict[str, str], str]],
    Field(
        None,
        description=(
            "The additional_hosts parameter is a dictionary of hostname (the key) "
            "to IP address (the value) for hosts that do not have DNS records. "
            "This includes CTF targets or web server virtual hosts found during "
            "other scans. If you know the IP address for a host, be sure to include "
            "these in the additional_hosts parameter. If a hostname does not resolve "
            "try using the additional_hosts parameter with the target IP address."
        )
    )
]

ProcessEnvField: TypeAlias = Annotated[Optional[Union[Dict[str, str], str]], Field(
    None,
    description="Environment variables to set for the process."
)]

CookiesField: TypeAlias = Annotated[
    Optional[Union[Dict[str, str], str]], Field(description="Name, value pairs for cookies to send with each request.")
]

UserAgentField: TypeAlias = Annotated[
    Optional[str],
    Field(description=(
        "The user_agent can be used to specify the \"User-Agent\" request header. This is useful if a "
        "particular browser needs to be spoofed or the user requests extra information in the user "
        "agent header to identify themselves as a bug bounty hunter."
    ))]

RequestHeadersField: TypeAlias = Annotated[
    Optional[Union[Dict[str, str], str]],
    Field(None, description="Extra HTTP headers sent with the request.")
]

RequestParamsField: TypeAlias = Annotated[
    Optional[Union[Dict[str, str], str]], Field(),
    Field(description="name, value pairs for GET or POST parameters")
]

class ShyHurricaneMCPServer(MCPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_world = True
        self.running_tools: set[str] = set()
        self._running_tool_counts: dict[str, int] = {}

    async def list_tools(self) -> list[Tool]:
        logger.info("Listing tools")
        tools = await super().list_tools()
        if not self.open_world:
            logger.info(f"Filtering tools for open_world = {self.open_world}")

            def tool_filter(tool: Tool) -> bool:
                if tool.annotations is None:
                    return True
                if not self.open_world:
                    if tool.annotations.open_world_hint:
                        return False
                return True

            tools = list(filter(tool_filter, tools))
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Context | None = None):
        self.running_tools.add(name)
        self._running_tool_counts[name] = self._running_tool_counts.get(name, 0) + 1
        try:
            return await super().call_tool(name, arguments, context)
        finally:
            remaining = self._running_tool_counts[name] - 1
            if remaining:
                self._running_tool_counts[name] = remaining
            else:
                del self._running_tool_counts[name]
                self.running_tools.discard(name)


mcp_server_instructions = """
This server assists penetration testers, red team operators and security auditors who are skilled in offensive security, vulnerability discovery, and exploitation.

---

## Tool-selection guidelines:

**Prefer indexed-information tools** (`find_web_resource`, `find_domains`, `query_findings`, etc.) over direct interaction.  
- They are faster, read-only and safe for production.  
- Use them first for enumeration, code search, log review and context building.

**Prefer task-specific tools** (`spider_website`, `directory_buster`, `index_http_url`, etc.) over command execution.
- They index content for faster retrieval and rich queries.
- They are purpose built with appropriate logging and rate limits.

---

## Operational / safety rules:

- Respect the user-supplied scope (URL, host, IP, subnet). No scanning or fetching from out-of-scope assets.
- Strip or mask sensitive PII in tool outputs: keep only the minimal sample needed to prove access.
"""


mcp_instance = ShyHurricaneMCPServer(
    "shyhurricane",
    lifespan=app_lifespan,
    instructions=mcp_server_instructions,
    middleware=[client_state_middleware],
)


def assert_elicitation(ctx: ServerContext):
    if ctx.disable_elicitation:
        raise MCPError(INVALID_REQUEST, "elicitation disabled")


async def log_history(ctx: Context, data: Dict[str, Any]):
    data["timestamp"] = datetime.now().isoformat()
    try:
        data_str = json.dumps(data)
    except (TypeError, ValueError):
        data_str = repr(data)
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
    try:
        data_str = json.dumps(data)
    except (TypeError, ValueError):
        data_str = repr(data)
    logger.info(f"{title}: {data_str}")


def get_additional_hosts(ctx: Context, additional_hosts: Dict[str, str] = None) -> Dict[str, str]:
    cached_get_additional_hosts = ctx.request_context.lifespan_context.cached_get_additional_hosts
    if not additional_hosts:
        return cached_get_additional_hosts
    validated: Dict[str, str] = {}
    for host, ip in (additional_hosts or {}).items():
        try:
            if validators.domain(host) == True and ipaddress.ip_address(ip):  # noqa: E712
                validated[host] = ip
                cached_get_additional_hosts[host] = ip
        except (ValueError, ValidationError):
            pass
    return cached_get_additional_hosts | validated


def get_additional_http_headers(ctx: Context, additional_http_headers: Dict[str, str] = None) -> Dict[str, str]:
    http_headers = ctx.request_context.lifespan_context.http_headers
    return http_headers | (additional_http_headers or {})
