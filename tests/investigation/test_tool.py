"""The public tool reads only materialized results and supports saved pages."""

from contextlib import closing
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from shyhurricane.investigation.storage import CorrelationStore
from shyhurricane.mcp_server.tools import investigation as tool
from tests.investigation.test_storage import publish


@pytest.fixture(autouse=True)
def result_store(tmp_path, monkeypatch):
    from shyhurricane import result_pages

    store = result_pages.ResultPageStore(str(tmp_path / "saved_pages"))
    monkeypatch.setattr(result_pages, "get_result_store", AsyncMock(return_value=store))
    yield store
    store.close()


async def test_tool_pagination_filters_and_pending_fallback(monkeypatch):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    monkeypatch.setattr(tool, "get_server_context", AsyncMock(return_value=SimpleNamespace(db="test")))
    monkeypatch.setattr(tool, "log_tool_history", AsyncMock())
    monkeypatch.setattr(tool, "report_progress", AsyncMock())
    result = await tool.find_investigation_targets(None, "example.com")
    assert result.results == [] and result.analysis_gaps
    with closing(CorrelationStore("test")) as store:
        publish(store, "a")
        publish(store, "b")
    result = await tool.find_investigation_targets(None, "example.com", limit=1)
    assert len(result.results) == 1
    assert result.pagination.total_items == 2
    assert set(result.findings) == set(result.results[0]["finding_ids"])
    saved = await get_result_page(None, result.pagination.next_page_token)
    assert saved.source_tool == "find_investigation_targets"
    assert len(saved.result.results) == 1
    assert set(saved.result.findings) == set(saved.result.results[0]["finding_ids"])
    assert saved.result.pagination.next_page_token is None
    with pytest.raises(ToolError, match="Unsupported vulnerability_type"):
        await tool.find_investigation_targets(None, "example.com", vulnerability_type="SQL stuff")
    with pytest.raises(ToolError):
        await tool.find_investigation_targets(None, "https://example.com/?invalid=1")


async def test_tool_is_registered_read_only_and_schema_is_optional():
    from shyhurricane.mcp_server import mcp_instance

    tools = {item.name: item for item in await mcp_instance.list_tools()}
    assert tools["find_investigation_targets"].annotations.read_only_hint
    assert tools["find_investigation_targets"].annotations.open_world_hint is False
    assert tools["save_finding"].input_schema["properties"]["metadata"]
