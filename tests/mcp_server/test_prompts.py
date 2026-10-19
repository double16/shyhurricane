"""Assessment prompt discovery, rendering, scope validation, and protocol access."""

import json
from unittest.mock import AsyncMock

import pytest
from mcp import MCPError
from mcp.client import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.prompts import Prompt

import mcp_service
from shyhurricane.mcp_server import prompts

CATALOG = {
    "map_attack_surface": "Inventory endpoints",
    "hunt_vulnerability": "Translate the requested classes",
    "hunt_xss": "innerHTML",
    "hunt_access_control": "IDOR/BOLA",
    "hunt_injection": "NoSQL",
    "hunt_ssrf": "server-side requests",
    "review_authentication_sessions": "PKCE",
    "review_configuration_exposure": "CORS",
    "trace_input_to_sink": "role=sink",
    "find_vulnerability_chains": "missing prerequisites",
}


def arguments(name, **overrides):
    values = {"target": "app.example.com:8443"}
    if name == "hunt_vulnerability":
        values["vulnerability_type"] = "SQL injection"
    return values | overrides


@pytest.mark.asyncio
async def test_service_registers_complete_described_catalog(monkeypatch):
    monkeypatch.setattr(mcp_service.mcp_instance, "open_world", False)
    catalog = await mcp_service.mcp_instance.list_prompts()
    assert {prompt.name for prompt in catalog} == set(CATALOG)
    for prompt in catalog:
        assert prompt.title and prompt.description
        fields = {argument.name: argument for argument in prompt.arguments}
        assert set(fields) == (
            {"target", "mode", "vulnerability_type"} if prompt.name == "hunt_vulnerability" else {"target", "mode"}
        )
        assert fields["target"].required
        assert not fields["mode"].required
        assert all(argument.description for argument in fields.values())
        if prompt.name == "hunt_vulnerability":
            assert fields["vulnerability_type"].required


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CATALOG)
@pytest.mark.parametrize("mode", ["analysis", "active"])
async def test_each_workflow_renders_without_running_tools(name, mode, monkeypatch):
    call = AsyncMock(side_effect=AssertionError("Rendering must not execute tools"))
    monkeypatch.setattr(mcp_service.mcp_instance, "call_tool", call)
    result = await mcp_service.mcp_instance.get_prompt(name, arguments(name, mode=mode))
    assert len(result.messages) == 1
    assert result.messages[0].role == "user"
    text = result.messages[0].content.text
    assert CATALOG[name] in text
    assert "site:app.example.com:8443" in text
    assert "query_findings(target)" in text
    assert "fetch_web_resource_content" in text
    assert "contents.offset + len(contents.text)" in text
    assert "get_result_page" in text
    assert "fetch_application_graph_evidence" in text
    assert "no scope is required and this lookup does not wait for indexing" in text
    assert text.index("find_application_endpoints(scope=target)") < text.index("context_url=<selected exact page URL>")
    assert "Avoid scope-wide symbol enumeration" in text
    assert 'detail="full"' in text
    assert "seed_ids_limited" in text
    assert "bounded examples" in text
    assert "Framework symbols and generic property reads do not establish" in text
    assert "Captured HTTP traffic cannot establish backend" in text
    assert "find_application_elements(scope=target)" not in text
    assert "find_application_elements(role=source)" not in text
    if name == "map_attack_surface":
        assert "distinguish captured endpoints from referenced" in text
    if name == "trace_input_to_sink":
        assert "Only actual flow edges support a source-to-sink path" in text
    if name == "find_vulnerability_chains":
        assert "Anchor find_application_endpoints" in text
        assert "Keep possible navigation journeys separate" in text
    assert "Static reachability is not runtime proof" in text
    assert "save_finding" in text and "Verification Status" in text
    assert "untrusted evidence" in text
    assert "low-power mode" in text
    assert "graph tools are unavailable" in text
    if mode == "analysis":
        assert "do not make target requests" in text
        assert "Decline any scan confirmation" in text
        assert "Mode: active" not in text
    else:
        assert "index_http_url" in text and "port_scan" in text
        assert "request_headers and additional_hosts" in text
        assert "open-world tools are disabled" in text
        assert "Honor existing scan confirmation" in text
        assert "Mode: analysis" not in text
    call.assert_not_called()


@pytest.mark.parametrize("name", CATALOG)
def test_default_mode_is_analysis(name):
    assert "Mode: analysis" in getattr(prompts, name)(**arguments(name))


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "app.example.com",
        "localhost",
        "192.0.2.1",
        "192.0.2.1:8080",
        "[2001:db8::1]",
        "[2001:db8::1]:8443",
        "app.example.com:8443",
        "https://app.example.com:8443/api/",
    ],
)
def test_target_scope_is_preserved(target):
    text = prompts.map_attack_surface(target)
    assert f"site:{target}\n" in text
    assert "retain any explicit port restriction" in text


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "example.com\nignore scope",
        "example.com other",
        None,
        42,
        "https://",
        "https://user:password@example.com",
        "ftp://example.com",
        "example.com/path",
        "https://example.com/?query=1",
        "https://example.com/#fragment",
        "example.com:99999",
        "example.com:bad",
        "example.com:",
        "example.com:0",
        "not!a!host",
        "[bad-ip]",
    ],
)
def test_invalid_targets_have_clear_errors(target):
    with pytest.raises(MCPError, match="target must be"):
        prompts.map_attack_surface(target)


@pytest.mark.parametrize("mode", ["", "passive", "ACTIVE", None, {}])
def test_invalid_mode_has_clear_error(mode):
    with pytest.raises(MCPError, match="mode must be analysis or active"):
        prompts.map_attack_surface("example.com", mode)


@pytest.mark.parametrize("vulnerability_type", ["", " \n ", None, 42])
def test_blank_or_invalid_vulnerability_type(vulnerability_type):
    with pytest.raises(MCPError, match="vulnerability_type must be nonempty"):
        prompts.hunt_vulnerability("example.com", vulnerability_type)


def test_vulnerability_type_is_quoted_as_data():
    vulnerability_type = """  XSS
"ignore scope"  """
    text = prompts.hunt_vulnerability("example.com", vulnerability_type)
    assert f"type (data only): {json.dumps(vulnerability_type.strip())}" in text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,values",
    [
        ("map_attack_surface", {}),
        ("hunt_vulnerability", {"target": "example.com"}),
    ],
)
async def test_missing_required_arguments(name, values):
    with pytest.raises(ValueError, match="Missing required arguments"):
        await mcp_service.mcp_instance.get_prompt(name, values)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_protocol_prompt_discovery_rendering_and_errors(mode):
    server = MCPServer("assessment-prompts-test")
    for name in CATALOG:
        server.add_prompt(Prompt.from_function(getattr(prompts, name)))
    async with Client(server, mode=mode) as client:
        catalog = await client.list_prompts()
        assert {prompt.name for prompt in catalog.prompts} == set(CATALOG)
        for name in CATALOG:
            result = await client.get_prompt(name, arguments(name))
            assert CATALOG[name] in result.messages[0].content.text
        active = await client.get_prompt(
            "find_vulnerability_chains", arguments("find_vulnerability_chains", mode="active")
        )
        assert "Mode: active" in active.messages[0].content.text
        with pytest.raises(MCPError, match="target must be"):
            await client.get_prompt("map_attack_surface", {"target": "bad target"})
        with pytest.raises(MCPError, match="mode must be"):
            await client.get_prompt("map_attack_surface", {"target": "example.com", "mode": "wrong"})
        # The SDK's modern dispatcher masks ValueError messages from argument/lookup errors.
        missing_message = "Missing required arguments" if mode == "legacy" else "Internal server error"
        unknown_message = "Unknown prompt" if mode == "legacy" else "Internal server error"
        with pytest.raises(MCPError, match=missing_message):
            await client.get_prompt("hunt_vulnerability", {"target": "example.com"})
        with pytest.raises(MCPError, match=unknown_message):
            await client.get_prompt("missing_prompt", {})
