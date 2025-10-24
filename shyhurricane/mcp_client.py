#!/usr/bin/env python3
import os
import re
import json
import sys
from pathlib import Path
from typing import Any, List, Union, Tuple, Callable

from haystack.tools import Toolset
from haystack_integrations.tools.mcp import MCPToolset
from haystack_integrations.tools.mcp.mcp_tool import (
    StdioServerInfo,
    StreamableHttpServerInfo,
    SSEServerInfo, MCPServerInfo,
)
from mcp import Tool

ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def interpolate_env(value: Any) -> Any:
    """
    Recursively interpolate environment variables in strings of the form "${KEY}".
    """
    if isinstance(value, str):
        match = ENV_PATTERN.fullmatch(value.strip())
        if match:
            key = match.group(1)
            return os.environ.get(key, value)
        # handle partial strings like "Bearer ${TOKEN}"
        return ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
    elif isinstance(value, dict):
        return {k: interpolate_env(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [interpolate_env(v) for v in value]
    return value


def load_mcp_servers_from_json(config_path: Union[str, Path]) -> List[Union[MCPServerInfo]]:
    """Load MCP server configurations and instantiate the appropriate server info classes."""
    path = Path(config_path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    servers: List[Union[MCPServerInfo]] = []

    for entry in data:
        entry = interpolate_env(entry)
        transport = entry.get("transport")

        if transport == "stdio":
            servers.append(
                StdioServerInfo(
                    command=entry["command"],
                    args=entry.get("args"),
                    env=entry.get("env"),
                    max_retries=entry.get("max_retries", 3),
                    base_delay=entry.get("base_delay", 1.0),
                    max_delay=entry.get("max_delay", 30.0),
                )
            )
        elif transport == "streamable_http":
            servers.append(
                StreamableHttpServerInfo(
                    url=entry["url"],
                    token=entry.get("token"),
                    timeout=entry.get("timeout", 30),
                    max_retries=entry.get("max_retries", 3),
                    base_delay=entry.get("base_delay", 1.0),
                    max_delay=entry.get("max_delay", 30.0),
                )
            )
        elif transport == "sse":
            servers.append(
                SSEServerInfo(
                    url=entry.get("url"),
                    base_url=entry.get("base_url"),
                    token=entry.get("token"),
                    timeout=entry.get("timeout", 30),
                    max_retries=entry.get("max_retries", 3),
                    base_delay=entry.get("base_delay", 1.0),
                    max_delay=entry.get("max_delay", 30.0),
                )
            )
        else:
            raise ValueError(f"Unsupported transport type: {transport}")

    return servers


def create_mcp_toolset(
        servers: List[Union[MCPServerInfo]],
        shim: Callable[[Tool], Tool] = None,
) -> Tuple[Toolset, List[MCPToolset]]:
    """
    Create and initialize a Toolset including tools from all servers. Return the list of MCPToolset to be properly
    closed.
    """
    mcp_toolsets = []
    tools = []

    for server in servers or [StreamableHttpServerInfo(url="http://127.0.0.1:8000/mcp/")]:
        toolset = MCPToolset(
            server_info=server,
            invocation_timeout=600.0,
            eager_connect=True,
        )
        mcp_toolsets.append(toolset)
        if shim is not None:
            tools.extend(list(map(lambda t: shim(t), toolset)))
        else:
            if len(servers) < 2:
                return toolset, mcp_toolsets
            tools.extend(list(toolset))

    return Toolset(tools=tools), mcp_toolsets


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mcp_servers.json>")
        sys.exit(1)

    config_path = sys.argv[1]
    servers = load_mcp_servers_from_json(config_path)
    print(f"Loaded {len(servers)} MCP server configurations")

    toolset, mcp_toolsets = create_mcp_toolset(servers)
    print(f"Created MCPToolset with {len(toolset)} tools")
    for t in toolset:
        print(f" - {t.name}")

    for s in mcp_toolsets:
        s.close()


if __name__ == "__main__":
    main()
