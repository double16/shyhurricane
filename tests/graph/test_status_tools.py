from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.status import graph_status
from shyhurricane.mcp_server.tools import application_graph as tools


async def test_graph_status_handles_outage_and_reports_backlog(graph_paths, event):
    assert (await graph_status(SimpleNamespace()))["healthy"] is None
    artifacts = ArtifactStore("db")
    artifacts.status(event()["id"], "failed", "bad")
    artifacts.close()
    context = SimpleNamespace(
        db="db",
        graph_store=SimpleNamespace(statistics=lambda: {"entities": 2}),
        health_monitor=SimpleNamespace(neo4j_healthy=True),
    )
    result = await graph_status(context)
    await context._graph_statistics_cache.task
    result = await graph_status(context)
    assert result["entities"] == 2 and result["analyses"] == {"failed": 1}
    context.graph_store.statistics = lambda: 1 / 0
    context._graph_statistics_cache.next_refresh = 0
    await graph_status(context)
    await context._graph_statistics_cache.task
    assert "statistics_error" in await graph_status(context)
    context.health_monitor.neo4j_healthy = False
    assert (await graph_status(context))["statistics_stale"]


async def test_all_tools_dispatch_read_only_queries(monkeypatch):
    calls = []

    async def query(ctx, name, operation, scope, **kwargs):
        calls.append((name, operation, scope, kwargs))
        return {"results": [], "instructions": "partial"} if operation != "evidence" else {"id": "evidence"}

    monkeypatch.setattr(tools, "query", query)
    assert not (await tools.find_application_elements.__wrapped__(None, "example.com")).results
    await tools.find_application_relationships.__wrapped__(None, "example.com", "id")
    await tools.trace_application_data_flow.__wrapped__(None, "example.com", "id")
    await tools.find_user_journey_paths.__wrapped__(None, "example.com", "/start", "/end")
    assert await tools.fetch_application_graph_evidence(None, "example.com", "evidence") == {"id": "evidence"}
    await tools.find_application_endpoints.__wrapped__(
        None, "example.com", url="https://example.com/blog", method="POST"
    )
    assert calls[-1][1] == "endpoints"
    assert calls[-1][3]["method"] == "POST"
    assert len(calls) == 6
    assert calls[2][3]["mode"] == "flow" and calls[3][3]["mode"] == "journey"


async def test_query_errors_are_explicit_and_no_fetch_occurs(monkeypatch):
    server = SimpleNamespace(graph_store=None)
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    monkeypatch.setattr(tools, "log_tool_history", AsyncMock())
    with pytest.raises(ToolError, match="unavailable"):
        await tools.query(None, "test", "elements", "example.com")
    server.graph_store = object()
    monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(elements=lambda scope: {"results": []}))
    assert await tools.query(None, "test", "elements", "example.com") == {"results": []}
    for error in (ValueError("invalid scope"), RuntimeError("database error")):

        def fail(scope):
            raise error

        monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(elements=fail))
        with pytest.raises(ToolError):
            await tools.query(None, "test", "elements", "example.com")


async def test_graph_tools_publish_complete_argument_schemas():
    names = {
        "find_application_endpoints",
        "find_application_elements",
        "find_application_relationships",
        "trace_application_data_flow",
        "find_user_journey_paths",
        "fetch_application_graph_evidence",
    }
    registered = {tool.name: tool for tool in await tools.mcp_instance.list_tools() if tool.name in names}
    assert registered.keys() == names
    required = {
        "find_application_endpoints": {"scope"},
        "find_application_elements": {"scope"},
        "find_application_relationships": {"scope", "element_id"},
        "trace_application_data_flow": {"scope", "start"},
        "find_user_journey_paths": {"scope", "start", "end"},
        "fetch_application_graph_evidence": {"scope", "evidence_id"},
    }
    for tool in registered.values():
        assert set(tool.input_schema["required"]) == required[tool.name]
        properties = tool.input_schema["properties"]
        assert "ctx" not in properties
        assert all(field.get("description", "").strip() for field in properties.values())
        assert properties["scope"]["type"] == "string"
        assert "scope" in tool.input_schema["required"]
        if "limit" in properties:
            assert properties["limit"]["default"] == (5 if tool.name == "find_application_endpoints" else 20)
            assert properties["limit"]["minimum"] == 1
            assert properties["limit"]["maximum"] == 1000
            assert properties["historical"]["default"] is False
            assert properties["as_of"]["default"] is None
            assert "Unix seconds" in properties["as_of"]["description"]
            assert properties["limit"]["type"] == "integer"
            assert properties["historical"]["type"] == "boolean"
            assert properties["as_of"]["anyOf"] == [{"type": "number"}, {"type": "null"}]
        if "detail" in properties:
            assert properties["detail"]["default"] == "compact"
            assert properties["detail"]["enum"] == ["compact", "full"]
        if "direction" in properties:
            assert properties["direction"]["enum"] == ["forward", "backward"]
            assert properties["direction"]["default"] == "forward"
        if "max_depth" in properties:
            depth = properties["max_depth"]
            assert depth["minimum"] == 1
            assert (depth["default"], depth["maximum"]) == (
                (1, 3) if tool.name == "find_application_relationships" else (8, 32)
            )

    elements = registered["find_application_elements"].input_schema["properties"]
    relationships = registered["find_application_relationships"].input_schema["properties"]
    assert elements["role"]["default"] is None
    assert elements["role"]["anyOf"] == [
        {"enum": ["source", "sink"], "type": "string"},
        {"type": "null"},
    ]
    assert elements["context_url"]["default"] is None
    assert elements["url"]["default"] is None
    assert elements["url"]["anyOf"] == [{"type": "string"}, {"type": "null"}]
    for properties, category in ((elements, "element"), (relationships, "relationship")):
        kinds = properties["kinds"]
        assert f"{category} kind strings" in kinds["description"]
        assert "case-sensitive" in kinds["description"]
        assert "means all kinds" in kinds["description"]
        assert kinds["default"] is None
        assert kinds["anyOf"] == [{"items": {"type": "string"}, "type": "array"}, {"type": "null"}]
    for name, arguments in (
        ("find_application_relationships", ["element_id"]),
        ("trace_application_data_flow", ["start", "end"]),
        ("find_user_journey_paths", ["start", "end"]),
    ):
        for argument in arguments:
            description = registered[name].input_schema["properties"][argument]["description"]
            assert "find_application_elements" in description
            assert "results[].id" in description
    evidence = registered["fetch_application_graph_evidence"].input_schema["properties"]["evidence_id"]
    assert "results[].steps[].evidence_id" in evidence["description"]
    for name in ("find_application_relationships", "trace_application_data_flow", "find_user_journey_paths"):
        assert name in evidence["description"]


@pytest.mark.parametrize(
    "tool_name",
    [
        "find_application_endpoints",
        "find_application_elements",
        "find_application_relationships",
        "trace_application_data_flow",
        "find_user_journey_paths",
    ],
)
async def test_graph_pages_retain_results_and_metadata(tool_name, tmp_path, monkeypatch):
    from shyhurricane import result_pages
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    store = result_pages.ResultPageStore(str(tmp_path))
    monkeypatch.setattr(result_pages, "get_result_store", AsyncMock(return_value=store))
    result = tools.GraphResult(
        results=[{"id": "one"}, {"id": "two"}],
        instructions="Candidates only",
        resolved_start_ids=["seed"],
        resolved_start_count=30,
        seed_ids_limited=True,
        retrieval_truncated=True,
        truncation_reasons=["entity_limit"],
    )
    first = await result_pages.paginate_result(tool_name, result, "results", 1, True)
    page = await get_result_page(None, first.pagination.next_page_token)
    assert page.source_tool == tool_name
    assert page.result.results == [{"id": "two"}]
    assert page.result.resolved_start_ids == ["seed"]
    assert page.result.resolved_start_count == 30 and page.result.seed_ids_limited
    assert page.result.retrieval_truncated and page.result.truncation_reasons == ["entity_limit"]
    previous = await get_result_page(None, page.result.pagination.previous_page_token)
    assert previous.result.results == first.results


async def test_endpoint_tool_paginates_defaults_and_filters(tmp_path, monkeypatch):
    from shyhurricane import result_pages
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    store = result_pages.ResultPageStore(str(tmp_path))
    monkeypatch.setattr(result_pages, "get_result_store", AsyncMock(return_value=store))
    query = AsyncMock(return_value={"results": [{"id": str(index)} for index in range(7)], "instructions": "partial"})
    monkeypatch.setattr(tools, "query", query)
    first = await tools.find_application_endpoints(None, "example.com", method="post", historical=True, as_of=42)
    assert len(first.results) == 5 and first.pagination.total_items == 7
    assert query.call_args.kwargs == {"url": None, "method": "post", "historical": True, "as_of": 42}
    second = await get_result_page(None, first.pagination.next_page_token)
    assert [item["id"] for item in second.result.results] == ["5", "6"]
    query.assert_awaited_once()
    with pytest.raises(ToolError, match="limit must be"):
        await tools.find_application_endpoints(None, "example.com", limit=0)
