#!/usr/bin/env python3
import json
import os
import tempfile
from pathlib import Path

import pytest
from haystack_integrations.tools.mcp.mcp_tool import (
    StdioServerInfo,
    StreamableHttpServerInfo,
    SSEServerInfo,
)
from shyhurricane.mcp_client import load_mcp_servers_from_json


@pytest.fixture
def temp_json_file():
    """Create a temporary JSON file with mixed MCP server configs."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    data = [
        {
            "transport": "stdio",
            "command": "python",
            "args": ["-m", "shyhurricane.server"],
            "env": {"API_KEY": "${API_KEY}"},
        },
        {
            "transport": "streamable_http",
            "url": "https://example.com/mcp",
            "token": "Bearer ${MCP_TOKEN}",
            "timeout": 45
        },
        {
            "transport": "sse",
            "url": "https://example.com/sse",
            "token": "${SSE_TOKEN}"
        }
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    yield Path(path)
    os.remove(path)


def test_load_mcp_servers_from_json_interpolates_env(temp_json_file, monkeypatch):
    """Ensure JSON configs load properly and environment interpolation works."""
    monkeypatch.setenv("API_KEY", "env-api-key")
    monkeypatch.setenv("MCP_TOKEN", "env-mcp-token")
    monkeypatch.setenv("SSE_TOKEN", "env-sse-token")

    servers = load_mcp_servers_from_json(temp_json_file)

    # Expect three servers: Stdio, StreamableHttp, SSE
    assert len(servers) == 3
    assert isinstance(servers[0], StdioServerInfo)
    assert isinstance(servers[1], StreamableHttpServerInfo)
    assert isinstance(servers[2], SSEServerInfo)

    # Verify environment variable interpolation
    assert servers[0].env["API_KEY"] == "env-api-key"
    assert servers[1].token == "Bearer env-mcp-token"
    assert servers[2].token == "env-sse-token"
