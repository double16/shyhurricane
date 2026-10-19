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


async def test_graph_status_reports_live_uri_without_successful_statistics(graph_paths):
    def fail():
        raise RuntimeError("statistics failure")

    context = SimpleNamespace(
        db="db", graph_store=SimpleNamespace(uri="bolt://localhost:7687", statistics=fail),
        health_monitor=SimpleNamespace(neo4j_healthy=True),
    )
    initial = await graph_status(context)
    assert initial["uri"] == "bolt://localhost:7687" and initial["healthy"]
    await context._graph_statistics_cache.task
    failed = await graph_status(context)
    assert failed["uri"] == initial["uri"] and failed["statistics_error"] == "RuntimeError"
    context._graph_statistics_cache.values["uri"] = "bolt://old:7687"
    assert (await graph_status(context))["uri"] == initial["uri"]


async def test_all_tools_dispatch_read_only_queries(monkeypatch):
    calls = []

    async def query(ctx, name, operation, scope, **kwargs):
        calls.append((name, operation, scope, kwargs))
        return {"results": [], "instructions": "partial"}

    monkeypatch.setattr(tools, "query", query)
    assert not (await tools.find_application_elements.__wrapped__(None, "example.com")).results
    await tools.find_application_relationships.__wrapped__(None, "example.com", "id")
    await tools.trace_application_data_flow.__wrapped__(None, "example.com", "id")
    await tools.find_user_journey_paths.__wrapped__(None, "example.com", "/start", "/end")
    await tools.find_application_endpoints.__wrapped__(
        None, "example.com", url="https://example.com/blog", method="POST"
    )
    assert calls[-1][1] == "endpoints"
    assert calls[-1][3]["method"] == "POST"
    assert len(calls) == 5
    assert calls[2][3]["mode"] == "flow" and calls[3][3]["mode"] == "journey"


@pytest.mark.parametrize("result", [{"id": "evidence", "url": "https://cdn.other.test/script.js"}, None])
@pytest.mark.parametrize("indexing_status", ["pending", "paused"])
async def test_evidence_reads_directly_without_scope_or_indexing(monkeypatch, result, indexing_status):
    from unittest.mock import Mock

    server = SimpleNamespace(graph_store=object(), indexing_status=indexing_status)
    history = AsyncMock()
    wait = AsyncMock(side_effect=AssertionError("Evidence must not wait"))
    scoped_query = AsyncMock(side_effect=AssertionError("Evidence must not use scoped queries"))
    lookup = Mock(return_value=result)
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    monkeypatch.setattr(tools, "log_tool_history", history)
    monkeypatch.setattr(tools, "wait_for_indexing", wait)
    monkeypatch.setattr(tools, "query", scoped_query)
    monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(evidence=lookup))
    assert await tools.fetch_application_graph_evidence(None, " \tevidence\n") == result
    lookup.assert_called_once_with("evidence")
    history.assert_awaited_once_with(None, "fetch_application_graph_evidence", evidence_id="evidence")
    wait.assert_not_awaited()
    scoped_query.assert_not_awaited()


async def test_evidence_errors_preserve_logging_and_hide_database_details(monkeypatch, caplog):
    from unittest.mock import Mock

    server = SimpleNamespace(graph_store=None)
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    monkeypatch.setattr(tools, "log_tool_history", AsyncMock())
    with pytest.raises(ToolError, match="Application graph is unavailable"):
        await tools.fetch_application_graph_evidence(None, "evidence")
    server.graph_store = object()
    failure = RuntimeError("private database failure")
    monkeypatch.setattr(
        tools, "GraphQuery", lambda store: SimpleNamespace(evidence=Mock(side_effect=failure))
    )
    with pytest.raises(ToolError, match="Application graph query failed") as caught:
        await tools.fetch_application_graph_evidence(None, "evidence")
    assert "private database failure" not in str(caught.value)
    record = next(record for record in caplog.records if record.name == tools.__name__)
    assert record.exc_info[1] is failure and record.exc_info[2] is not None
    assert "tool=fetch_application_graph_evidence operation=evidence evidence_id=evidence" in record.message


def test_evidence_schema_trims_id_without_coercing_invalid_types():
    from mcp.server.mcpserver.utilities.func_metadata import func_metadata
    from pydantic import ValidationError

    model = func_metadata(tools.fetch_application_graph_evidence, skip_names=["ctx"]).arg_model
    assert model.model_validate({"evidence_id": " \tevidence id\n"}).evidence_id == "evidence id"
    for value in (None, 3, []):
        with pytest.raises(ValidationError):
            model.model_validate({"evidence_id": value})


async def test_query_errors_are_explicit_and_no_fetch_occurs(monkeypatch):
    server = SimpleNamespace(graph_store=None)
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    monkeypatch.setattr(tools, "log_tool_history", AsyncMock())
    with pytest.raises(ToolError, match="unavailable"):
        await tools.query(None, "test", "elements", "example.com")
    server.graph_store = object()
    monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(elements=lambda scope: {"results": []}))
    result = await tools.query(None, "test", "elements", "example.com")
    assert result["results"] == []
    assert result["indexing"]["status"] == "unavailable"
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
        "fetch_application_graph_evidence": {"evidence_id"},
    }
    for tool in registered.values():
        assert set(tool.input_schema["required"]) == required[tool.name]
        properties = tool.input_schema["properties"]
        assert "ctx" not in properties
        assert all(field.get("description", "").strip() for field in properties.values())
        if tool.name == "fetch_application_graph_evidence":
            assert set(properties) == {"evidence_id"}
        else:
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


async def test_graph_query_waits_before_read_and_preserves_incomplete_results(monkeypatch):
    from shyhurricane.indexing_wait import IndexingStatus

    server = SimpleNamespace(graph_store=object())
    order = []

    async def wait(ctx, context, matches, **kwargs):
        order.append("wait")
        assert matches("https://sub.example.com/app")
        assert kwargs == {"graph": True}
        return IndexingStatus(status="timed_out", potentially_incomplete=True)

    def elements(scope):
        order.append("query")
        return None

    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    monkeypatch.setattr(tools, "log_tool_history", AsyncMock())
    monkeypatch.setattr(tools, "wait_for_indexing", wait)
    monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(elements=elements))
    result = await tools.query(None, "test", "elements", "example.com")
    assert order == ["wait", "query"]
    assert result["indexing"]["status"] == "timed_out"


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("find_application_endpoints", {"url": "https://example.com/a%20b", "method": "post"}),
        (
            "find_application_elements",
            {
                "role": "source",
                "context_url": "https://example.com/page",
                "url": "https://example.com/a%20b",
                "kinds": ["field", "custom kind"],
            },
        ),
        ("find_application_relationships", {"element_id": "opaque id", "direction": "backward", "kinds": ["LOADS"]}),
        ("trace_application_data_flow", {"start": "opaque id", "end": "other id", "direction": "forward"}),
        ("find_user_journey_paths", {"start": "https://example.com/a%20b", "end": "other id"}),
    ],
)
async def test_graph_input_validation_trims_before_literals_and_preserves_content(name, arguments, monkeypatch):
    from mcp.server.mcpserver.utilities.func_metadata import func_metadata

    function = getattr(tools, name)
    fields = {"scope": "example.com", **arguments}
    if name != "find_application_endpoints":
        fields["detail"] = "full"
    padded = {
        key: [f" \t{item}\n" for item in value] if isinstance(value, list) else f" \t{value}\n"
        for key, value in fields.items()
    }
    # The SDK builds this same model when registering MCP tools.
    model = func_metadata(function, skip_names=["ctx"]).arg_model
    validated = model.model_validate(padded).model_dump()
    for key, value in fields.items():
        assert validated[key] == value

    history = AsyncMock()
    monkeypatch.setattr(tools, "log_tool_history", history)
    server = SimpleNamespace(graph_store=object())
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=server))
    calls = []

    class Service:
        def __getattr__(self, operation):
            def run(scope, **kwargs):
                calls.append((scope, kwargs))
                return {"results": [], "instructions": "partial"}

            return run

    monkeypatch.setattr(tools, "GraphQuery", lambda store: Service())
    # Also exercise Python calls which bypass Pydantic validation.
    target = function.__wrapped__ if hasattr(function, "__wrapped__") else function
    await target(None, **padded)
    assert calls[0][0] == "example.com"
    assert history.await_args.kwargs["scope"] == "example.com"
    for key, value in fields.items():
        mapped = "start" if key == "element_id" else key
        if key != "scope":
            assert calls[0][1][mapped] == value


@pytest.mark.parametrize("value", [None, [], [""], ["  "], 3, "a  b", "a%20b"])
def test_graph_trim_preserves_nonboundary_content_and_types(value):
    assert tools.trim_input(value) == value


def test_graph_validation_rejects_invalid_literals_and_preserves_blank_filters():
    from mcp.server.mcpserver.utilities.func_metadata import func_metadata
    from pydantic import ValidationError

    model = func_metadata(tools.find_application_elements, skip_names=["ctx"]).arg_model
    result = model.model_validate({"scope": " example.com ", "kinds": [" \t"], "url": "  ", "role": None})
    assert result.kinds == [""] and result.url == "" and result.role is None
    assert model.model_validate({"scope": "example.com", "kinds": []}).kinds == []
    for role in (" SOURCE ", "  ", 3):
        with pytest.raises(ValidationError):
            model.model_validate({"scope": "example.com", "role": role})
    with pytest.raises(ValidationError):
        model.model_validate({"scope": 3})


async def test_unexpected_graph_failure_logs_original_traceback(monkeypatch, caplog):
    monkeypatch.setattr(tools, "log_tool_history", AsyncMock())
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=SimpleNamespace(graph_store=object())))
    failure = RuntimeError("original database failure")

    def fail(scope):
        raise failure

    monkeypatch.setattr(tools, "GraphQuery", lambda store: SimpleNamespace(elements=fail))
    with caplog.at_level("ERROR", logger=tools.__name__):
        with pytest.raises(ToolError, match="Application graph query failed") as caught:
            await tools.query(None, "find_application_elements", "elements", " example.com ")
    assert caught.value.__cause__ is failure
    record = next(record for record in caplog.records if record.name == tools.__name__)
    assert record.exc_info[1] is failure and record.exc_info[2] is not None
    assert "tool=find_application_elements operation=elements scope=example.com" in record.message
    assert "RuntimeError: original database failure" in caplog.text
    assert "Traceback" in caplog.text
    assert "original database failure" not in str(caught.value)

    caplog.clear()
    with pytest.raises(ToolError, match="scope"):
        await tools.query(None, "find_application_elements", "elements", "   ")
    monkeypatch.setattr(tools, "get_server_context", AsyncMock(return_value=SimpleNamespace(graph_store=None)))
    with pytest.raises(ToolError, match="unavailable"):
        await tools.query(None, "find_application_elements", "elements", "example.com")
    assert not [record for record in caplog.records if record.name == tools.__name__]


async def test_reference_cache_shared_by_status_calls_while_work_counts_stay_fresh(graph_paths, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "shyhurricane.graph.status.ReferenceStatistics.statistics",
        lambda self: calls.append(1) or {"unresolved_references": 4},
    )
    context = SimpleNamespace(
        db="db", graph_store=SimpleNamespace(uri="bolt://localhost:7687"),
        health_monitor=SimpleNamespace(neo4j_healthy=False),
    )
    initial = await graph_status(context)
    assert initial["reference_statistics_stale"]
    await context._graph_reference_cache.task
    task = context._graph_reference_cache.task
    artifacts = ArtifactStore("db")
    artifacts.status("new-work", "failed", "test")
    artifacts.close()
    refreshed = await graph_status(context)
    assert refreshed["unresolved_references"] == 4 and not refreshed["reference_statistics_stale"]
    assert refreshed["analyses"] == {"failed": 1}
    assert calls == [1] and context._graph_reference_cache.task is task


async def test_monitor_status_uses_activity_without_estimates_or_reference_scans(graph_paths):
    from unittest.mock import Mock

    store = SimpleNamespace(
        uri="bolt://localhost:7687", activity=Mock(return_value={"publication_revision": 19}),
        statistics=Mock(side_effect=AssertionError("Expensive statistics must not run")),
    )
    context = SimpleNamespace(db="db", graph_store=store, health_monitor=SimpleNamespace(neo4j_healthy=True))
    first = await graph_status(context, include_estimates=False)
    assert first["activity_stale"]
    await context._graph_activity_cache.task
    result = await graph_status(context, include_estimates=False)
    assert result["publication_revision"] == 19 and not result["activity_stale"]
    assert result["analyses"] == {} and result["uri"] == store.uri
    assert not hasattr(context, "_graph_statistics_cache") and not hasattr(context, "_graph_reference_cache")
    assert "current" not in result and "unresolved_references" not in result
    store.statistics.assert_not_called()
    store.activity.assert_called_once()


async def test_status_exposes_continuation_progress_and_failures(graph_paths, event):
    from shyhurricane.graph.continuations import Continuations

    artifacts = ArtifactStore("db")
    jobs = Continuations(artifacts)
    capture = event()
    key = jobs.enqueue(capture, capture, False)
    state = jobs.load(key)
    state["stage"] = "planning"
    state["contexts"] = {"one": {"id": "one"}}
    state["planner"] = {"cursor": {"context": 1}}
    jobs.save(key, state, status="failed", error="deadline")
    context = SimpleNamespace(db="db", graph_store=object(), health_monitor=SimpleNamespace(neo4j_healthy=False))
    result = await graph_status(context, include_estimates=False)
    progress = result["continuations"]
    assert progress["failed"] == 1 and progress["pending"] == progress["running"] == 0
    assert progress["stage"] == "planning" and progress["contexts_completed"] == progress["contexts_discovered"] == 1
    assert progress["checkpoint_age_seconds"] >= 0
    artifacts.close()
