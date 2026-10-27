"""Assessment prompt discovery, rendering, scope validation, and protocol access."""

import ast
import json
from unittest.mock import AsyncMock

import pytest
from jsonschema import Draft202012Validator
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
    assert "query_findings using the explicit site:" in text
    assert "retrieve all scoped findings" in text
    assert "after the scope predicates in query_findings" in text
    assert "page exhaustion does not establish completeness" in text
    assert "URL filters omit host-level findings" in text
    assert "fetch_web_resource_content" in text
    assert "contents.offset + len(contents.text)" in text
    assert "get_result_page" in text
    assert "fetch_application_graph_evidence" in text
    assert "no scope is required and this lookup does not wait for indexing" in text
    assert text.index('find_application_endpoints(scope=target, detail="inventory")') < text.index("context_url=<selected exact page URL>")
    assert "Avoid scope-wide symbol enumeration" in text
    assert 'detail="full"' in text
    assert "seed_ids_limited" in text
    assert 'detail="summary" with an exact url' in text
    assert "Avoid domain-wide summaries" in text
    assert "Inventory omits uncomputed sections" in text
    assert "Unknown capture status" in text
    assert "options are separate from endpoint inventory/summary" in text
    assert "bounded examples" in text
    assert "Framework symbols and generic property reads do not establish" in text
    assert "Captured HTTP traffic cannot establish backend" in text
    assert "find_application_elements(scope=target)" not in text
    assert "find_application_elements(role=source)" not in text
    if name == "map_attack_surface":
        assert 'detail="inventory", select URLs' in text
        assert "distinguish captured endpoints from referenced" in text
    if name == "trace_input_to_sink":
        assert "For a known endpoint, skip inventory" in text
        assert "Only actual flow edges support a source-to-sink path" in text
    if name == "find_vulnerability_chains":
        assert 'queries with detail="summary" and exact url' in text
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
        "https://app.example.com/",
        "http://app.example.com:8080/",
    ],
)
def test_target_scope_is_preserved(target):
    text = prompts.map_attack_surface(target)
    assert f"site:{target}\n" in text
    finding_scope = json.dumps(f"site:{target}")
    assert f"query_findings(query={finding_scope})" in text
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
        for target in ("https://example.com/", "https://example.com:8443/api/", "[2001:db8::1]:8443"):
            scoped = await client.get_prompt("map_attack_surface", {"target": target})
            finding_scope = json.dumps(f"site:{target}")
            assert f"query_findings(query={finding_scope})" in scoped.messages[0].content.text
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


@pytest.mark.parametrize("name", CATALOG)
def test_focused_prompts_render_semantic_call_and_inventory_remains_exhaustive(name):
    text = getattr(prompts, name)(**arguments(name))
    lookup = next(line for line in text.splitlines() if line.startswith("Scoped finding lookup:"))
    focused = name.startswith("hunt_") or name.startswith("review_")
    assert ("site:app.example.com:8443 " in lookup) == focused
    if name == "hunt_vulnerability":
        assert 'query="site:app.example.com:8443 SQL injection"' in lookup


CALL_EXAMPLES = [
    'find_application_endpoints(scope=target, detail="inventory")',
    "find_urls(host_query=target)",
    "find_hosts(domain_query=target)",
    "find_netloc(domain_query=target)",
    "fetch_web_resource_content(url=resource.uri)",
    "get_result_page(page_token=pagination.next_page_token)",
    "continue_application_graph_query(token=continuation_token)",
    "expand_application_graph_analysis(scope=target, capture_id=region.capture_id, unit_id=region.analysis_unit_id)",
    "find_application_relationships(scope=target, element_id=selected_id)",
    "trace_application_data_flow(scope=target, start=selected_id)",
    "find_user_journey_paths(scope=target, start=start_resource, end=end_resource)",
    "save_finding(target=affected_target, markdown=finding_markdown, title=finding_title)",
]
ACTIVE_CALL_EXAMPLES = [
    "spider_website(url=selected_url)",
    "directory_buster(url=selected_url)",
    "index_http_url(url=selected_url)",
    "port_scan(hostnames=[selected_hostname])",
]


def example_arguments(expression):
    """Resolve only documented example placeholders, without executing any calls."""
    values = {
        "target": "https://app.example.com:8443/api/",
        "resource.uri": "web://content/opaque-resource-id",
        "pagination.next_page_token": "opaque-page-token",
        "continuation_token": "opaque-continuation-token",
        "region.capture_id": "opaque-capture-id",
        "region.analysis_unit_id": "opaque-unit-id",
        "selected_id": "opaque-element-id",
        "start_resource": "opaque-start-id",
        "end_resource": "opaque-end-id",
        "affected_target": "https://app.example.com:8443/api/items",
        "finding_markdown": "# Title\nExample finding",
        "finding_title": None,
        "selected_url": "https://app.example.com:8443/api/items",
        "selected_hostname": "app.example.com",
    }
    call = ast.parse(expression, mode="eval").body
    result = {}
    for keyword in call.keywords:
        node = keyword.value
        if isinstance(node, ast.List):
            result[keyword.arg] = [values[ast.unparse(item)] for item in node.elts]
        elif isinstance(node, ast.Constant):
            result[keyword.arg] = node.value
        else:
            result[keyword.arg] = values[ast.unparse(node)]
    return call.func.id, result


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CATALOG)
@pytest.mark.parametrize("mode", ["analysis", "active"])
async def test_prompt_call_examples_match_registered_tool_schemas(name, mode):
    tools = {tool.name: tool.input_schema for tool in await mcp_service.mcp_instance.list_tools()}
    text = " ".join(getattr(prompts, name)(**arguments(name, mode=mode)).split())
    examples = CALL_EXAMPLES + (ACTIVE_CALL_EXAMPLES if mode == "active" else [])
    for expression in examples:
        assert expression in text
        tool, values = example_arguments(expression)
        schema = tools[tool]
        assert set(values) <= schema["properties"].keys()
        Draft202012Validator(schema).validate(values)
    assert "Only query_findings accepts score_threshold" in text
    assert "find_web_resources uses retrieval_limit" in text
    assert "Opaque IDs require scope" in text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,values",
    [
        ("continue_application_graph_query", {"continuation_token": "opaque-token"}),
        ("expand_application_graph_analysis", {
            "scope": "example.com", "capture_id": "capture", "analysis_unit_id": "unit",
        }),
        ("find_web_resources", {"query": "site:example.com", "score_threshold": 0.5}),
        ("save_finding", {"target": "example.com", "markdown": "# Finding"}),
        ("find_user_journey_paths", {"start": "opaque-start"}),
        ("find_application_endpoints", {"scope": "example.com", "detail": "full"}),
        ("find_application_relationships", {"element_id": "opaque-id", "max_depth": 4}),
        ("find_web_resources", {"query": "site:example.com", "retrieval_limit": 1001}),
    ],
)
async def test_inconsistent_example_arguments_are_rejected(tool, values):
    tools = {item.name: item.input_schema for item in await mcp_service.mcp_instance.list_tools()}
    schema = tools[tool]
    unknown = set(values) - schema["properties"].keys()
    assert unknown or list(Draft202012Validator(schema).iter_errors(values))
