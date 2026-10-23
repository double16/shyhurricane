from unittest.mock import AsyncMock

import pytest
from mcp import Client
from mcp.server import MCPServer
from pydantic import TypeAdapter, ValidationError

import shyhurricane.rate_limit as rate_limit
from shyhurricane.rate_limit import RateLimitRequestsPerSecondField, get_rate_limit_requests_per_second


@pytest.mark.parametrize(
    "target",
    ["example.com", "8.8.8.8", "2606:4700:4700::1111",
     " https://example.com:8443/path?query=yes ", "http://8.8.8.8:8080/",
     "https://[2606:4700:4700::1111]:8443/path", "example.com:8080/path"]
)
def test_get_rate_limit_requests_per_second_public(target):
    assert get_rate_limit_requests_per_second(target) == 5
    assert get_rate_limit_requests_per_second(target, None) == 5


@pytest.mark.parametrize(
    "target",
    ["target.local", "192.168.1.1", "127.0.0.1", "co.uk", "::1", "fc00::1",
     "http://192.168.1.1:8080/path", "http://[::1]:8000/", "localhost:8000", "http://", "http://[", ""]
)
def test_get_rate_limit_requests_per_second_private(target):
    assert get_rate_limit_requests_per_second(target) is None


@pytest.mark.parametrize("override", [0, 1, 7, 500])
@pytest.mark.parametrize("target", ["https://example.com/", "http://target.local/"])
def test_explicit_rate_bypasses_classification(monkeypatch, target, override):
    def unexpected_classification(target):
        pytest.fail("Explicit limits must bypass public-target classification")

    monkeypatch.setattr(rate_limit, "_is_public_target", unexpected_classification)
    assert get_rate_limit_requests_per_second(target, override) == override


@pytest.mark.parametrize("override", [-1, 1.5, 1.0, True, False, "5", "0", [], {}])
def test_invalid_overrides_are_rejected(override):
    with pytest.raises(ValueError, match="non-negative integer"):
        get_rate_limit_requests_per_second("https://example.com/", override)
    with pytest.raises(ValidationError):
        TypeAdapter(RateLimitRequestsPerSecondField).validate_python(override)


@pytest.mark.parametrize("override", [None, 0, 5])
def test_rate_field_accepts_valid_inputs(override):
    assert TypeAdapter(RateLimitRequestsPerSecondField).validate_python(override) == override


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["spider_website", "directory_buster"])
async def test_mcp_rate_schema_and_invalid_inputs(monkeypatch, tool_name):
    from shyhurricane.mcp_server.tools import directory_buster, find_web_resources

    module = find_web_resources if tool_name == "spider_website" else directory_buster
    context = AsyncMock()
    monkeypatch.setattr(module, "get_server_context", context)
    server = MCPServer("rate-limit-test")
    server.add_tool(getattr(module, tool_name))
    async with Client(server) as client:
        tool = (await client.list_tools()).tools[0]
        field = tool.input_schema["properties"]["rate_limit_requests_per_second"]
        assert field["default"] is None
        assert "rate_limit_requests_per_second" not in tool.input_schema["required"]
        integer = next(option for option in field["anyOf"] if option["type"] == "integer")
        assert integer["minimum"] == 0
        assert "requests/second" in integer["description"]
        for invalid in (-1, 1.5, 1.0, True, False, "5"):
            result = await client.call_tool(tool_name, {
                "url": "https://example.com/", "rate_limit_requests_per_second": invalid,
            })
            assert result.is_error, invalid
    context.assert_not_awaited()
