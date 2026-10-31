import json

import pytest
from haystack import Document
from qdrant_client.http import models as qm
from qdrant_client.local.payload_filters import check_filter

import shyhurricane.mcp_server.tools.findings as findings
from shyhurricane.finding_search import finding_search_metadata
from shyhurricane.target_info import parse_target_info
from shyhurricane.task_queue.finding_worker import FINDING_VERSION

REAL_ENQUEUE_FINDING = findings.enqueue_finding


async def noop(*args, **kwargs):
    return None


class Queue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class Store:
    def __init__(self, docs):
        self.docs = list(docs)
        self.filters = []

    async def scroll(self, **kwargs):
        assert kwargs["with_vectors"] is False
        assert "content" not in kwargs["with_payload"]
        self.filters.append(kwargs["scroll_filter"])
        records = [qm.Record(id=index, payload=doc.to_dict(flatten=False))
                   for index, doc in enumerate(self.docs)]
        records = [record for record in records if check_filter(
            kwargs["scroll_filter"], record.payload, record.id, {},
        )]
        offset = kwargs["offset"] or 0
        page = records[offset:offset + kwargs["limit"]]
        next_offset = offset + len(page)
        return page, next_offset if next_offset < len(records) else None

    async def retrieve(self, ids, **kwargs):
        assert kwargs["with_vectors"] is False
        return [qm.Record(id=index, payload=self.docs[index].to_dict(flatten=False)) for index in ids]


class ServerContext:
    def __init__(self, store=None):
        self.low_power = False
        self.task_queue = Queue()
        self.db = "test"
        self.finding_queue = Queue()
        self.stores = {"finding": store or Store([])}
        self.qdrant_client = self.stores["finding"]


def patch_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(findings, "get_server_context", get_fake_server_context)
    monkeypatch.setattr(findings, "log_tool_history", noop)
    monkeypatch.setattr(findings, "enqueue_finding", lambda db, item: server_context.finding_queue.put(item))


@pytest.mark.asyncio
async def test_save_finding_rejects_invalid_target(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await findings.save_finding(None, "not a target", "# finding", "Title")

    assert result.instructions == findings.finding_target_invalid_instructions
    assert ctx.finding_queue.items == []


@pytest.mark.asyncio
async def test_save_finding_enqueues_valid_target(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await findings.save_finding(None, "https://example.com", "# finding", "Title")

    assert ctx.task_queue.items == []
    assert result.instructions == "Finding is queued for saving; it may not be searchable immediately."
    assert ctx.finding_queue.items[0].target == "https://example.com"
    assert ctx.finding_queue.items[0].markdown == "# finding"
    assert ctx.finding_queue.items[0].title == "Title"


def finding_doc(**meta):
    base = {"title": "Finding", "url": "https://example.com/a", "host": "example.com", "domain": "example.com"}
    base.update(meta)
    info = parse_target_info(base["url"] or base["host"])
    base.update(version=FINDING_VERSION, port=info.port or (443 if info.url else 0))
    base.update(finding_search_metadata(base["url"], base["host"]))
    return Document(content="# body", meta=base)


@pytest.mark.asyncio
async def test_query_findings_by_url_and_limit(monkeypatch):
    store = Store([finding_doc(), finding_doc(url="https://example.com/a/child", title="Second")])
    patch_context(monkeypatch, ServerContext(store))

    result = await findings.query_findings(None, "https://example.com/a", limit=1)

    assert result.instructions == findings.finding_instructions
    assert result.limit == 1
    assert result.pagination.next_page_token is not None
    assert [finding.title for finding in result.findings] == ["Finding"]
    assert result.pagination.total_items == 2
    assert store.filters[0].must[1].key == "meta.search_host_suffixes"


@pytest.mark.asyncio
async def test_query_findings_by_netloc_host_domain_and_invalid(monkeypatch):
    store = Store([])
    patch_context(monkeypatch, ServerContext(store))

    netloc = await findings.query_findings(None, "example.com:8443")
    host = await findings.query_findings(None, "api.example.com")
    domain = await findings.query_findings(None, "example.com")
    invalid = await findings.query_findings(None, "not a target")

    assert netloc.instructions == findings.finding_not_found_instructions
    assert host.instructions == findings.finding_not_found_instructions
    assert domain.instructions == findings.finding_not_found_instructions
    assert "Invalid finding query" in invalid.instructions
    assert [call.must[1].key for call in store.filters] == ["meta.search_host_suffixes"] * 3


class FakeRequest:
    def __init__(self, content_type, chunks=None, form_data=None):
        self.headers = {"Content-Type": content_type}
        self.chunks = chunks or []
        self.form_data = form_data or {}

    async def body(self):
        return b"".join(self.chunks)

    async def stream(self):
        for chunk in self.chunks:
            yield chunk

    async def form(self):
        from starlette.datastructures import FormData

        return FormData([(key, item) for key, value in self.form_data.items()
                         for item in (value if isinstance(value, list) else [value])])


@pytest.mark.asyncio
@pytest.mark.parametrize("parameters", ["", "; charset=utf-8", '; charset="UTF-8"'])
@pytest.mark.parametrize("json_type", ["application/json", "text/json", "Application/JSON "])
async def test_save_finding_api_accepts_jsonl_and_form(monkeypatch, parameters, json_type):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    json_request = FakeRequest(
        f"{json_type}{parameters}",
        [
            (json.dumps({"target": "https://example.com/a", "title": "A", "markdown": "# A"}) + "\n").encode(),
            (json.dumps({"targets": ["example.com"], "title": "B", "markdown": "# B"}) + "\n").encode(),
        ],
    )
    form_request = FakeRequest(
        f"application/x-www-form-urlencoded{parameters}",
        form_data={"targets": ["example.com"], "title": "C", "markdown": "# C"},
    )

    json_response = await findings.save_finding_api(json_request)
    form_response = await findings.save_finding_api(form_request)

    assert json_response.status_code == 201
    assert form_response.status_code == 201
    assert [item.title for item in ctx.finding_queue.items] == ["A", "B", "C"]


@pytest.mark.asyncio
async def test_save_finding_api_accepts_json_with_charset(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    request = FakeRequest(
        "application/json; charset=utf-8",
        [json.dumps({"target": "example.com", "title": "Finding", "markdown": "# Café"},
                    ensure_ascii=False).encode("utf-8")],
    )

    response = await findings.save_finding_api(request)

    assert response.status_code == 201
    assert len(ctx.finding_queue.items) == 1
    assert ctx.finding_queue.items[0].markdown == "# Café"


@pytest.mark.asyncio
@pytest.mark.parametrize("content_type", [
    "", "text/plain", "text/plain; charset=utf-8", "application/json-invalid; charset=utf-8",
])
async def test_save_finding_api_rejects_bad_input(monkeypatch, content_type):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    assert (await findings.save_finding_api(FakeRequest(content_type))).status_code == 400
    assert (await findings.save_finding_api(
        FakeRequest("application/json; charset=utf-8", [b"{bad"])
    )).status_code == 400
    assert (await findings.save_finding_api(
        FakeRequest("application/json", [json.dumps({"target": "", "markdown": ""}).encode()])
    )).status_code == 400
    assert not ctx.finding_queue.items


@pytest.mark.asyncio
async def test_all_findings_are_saved_and_last_page_has_no_more(monkeypatch):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    store = Store([finding_doc(title=str(i)) for i in range(23)])
    patch_context(monkeypatch, ServerContext(store))
    first = await findings.query_findings(None, "https://example.com/a")
    assert len(first.findings) == 10
    assert first.pagination.total_items == 23
    assert first.pagination.next_page_token is not None
    second = (await get_result_page(None, first.pagination.next_page_token)).result
    assert len(second.findings) == 10 and second.pagination.next_page_token is not None
    last = (await get_result_page(None, second.pagination.next_page_token)).result
    assert len(last.findings) == 3
    assert {item.title for item in first.findings + second.findings + last.findings} == {str(i) for i in range(23)}
    assert last.pagination.next_page_token is None
    assert len(store.filters) == 1


@pytest.mark.asyncio
async def test_query_scope_filters_fallback_and_multiple_scroll_pages(monkeypatch):
    docs = [finding_doc(title=str(i)) for i in range(270)]
    docs += [finding_doc(url="", host="api.example.com", title="Host"),
             finding_doc(url="https://elsewhere.test/", host="elsewhere.test", title="Excluded")]
    store = Store(docs)
    patch_context(monkeypatch, ServerContext(store))
    result = await findings.query_findings(None, "https://example.com/", limit=1000)
    assert len(result.findings) == 271
    assert len(store.filters) == 2
    assert next(item for item in result.findings if item.title == "Host").target == "api.example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["inurl:admin", "site:example.com mime:text/html", "authentication bypass", "", " "])
async def test_invalid_query_does_not_initialize_database(monkeypatch, target):
    async def forbidden():
        raise AssertionError("Invalid queries must not initialize services")
    monkeypatch.setattr(findings, "log_tool_history", noop)
    monkeypatch.setattr(findings, "get_server_context", forbidden)
    result = await findings.query_findings(None, target)
    assert "Invalid finding query" in result.instructions
    assert not result.findings


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_query_predicates_through_protocol(monkeypatch, mode):
    from mcp.client import Client
    from mcp.server import MCPServer

    store = Store([
        finding_doc(url="https://example.com/admin.js", title="Script"),
        finding_doc(url="", host="api.example.com", title="Host"),
    ])
    patch_context(monkeypatch, ServerContext(store))
    server = MCPServer("finding-search-test")
    server.add_tool(findings.query_findings)
    async with Client(server, mode=mode) as client:
        for target, expected in [
            ("https://example.com/", {"Script", "Host"}),
            ("site:example.com inurl:admin ext:js", {"Script"}),
            ("site:https://example.com/", {"Script"}),
        ]:
            result = await client.call_tool("query_findings", {"query": target})
            assert not result.is_error
            assert {item["title"] for item in result.structured_content["findings"]} == expected
        invalid = await client.call_tool("query_findings", {"query": "inurl:admin"})
        assert "positive site:" in invalid.structured_content["instructions"]


@pytest.mark.asyncio
async def test_substring_false_positive_is_not_returned(monkeypatch):
    store = Store([finding_doc(url="https://example.com/abc--bcd"), finding_doc(url="https://example.com/abcd")])
    patch_context(monkeypatch, ServerContext(store))
    result = await findings.query_findings(None, "site:example.com inurl:abcd")
    assert [item.target for item in result.findings] == ["https://example.com/abcd"]


def test_enqueue_finding_survives_reopen_without_resuming_processing(monkeypatch, tmp_path):
    from shyhurricane.persistent_queue import open_persistent_queue
    from shyhurricane.task_queue.types import SaveFindingQueueItem

    path = str(tmp_path / "scan_findings")

    def open_queue(db, name, *, auto_resume):
        assert db == "test"
        assert name == "scan_finding_queue"
        assert auto_resume is False
        return open_persistent_queue(path, auto_resume=auto_resume)

    monkeypatch.setattr(findings, "get_persistent_queue", open_queue)
    first = SaveFindingQueueItem("example.com", "first", "First")
    second = SaveFindingQueueItem("example.com", "second", "Second")
    findings.enqueue_finding("test", first)
    worker = open_persistent_queue(path, auto_resume=False)
    try:
        processing = worker.get(block=False)
        findings.enqueue_finding("test", second)
        assert worker.get(block=False).markdown == "second"
        from persistqueue import Empty
        with pytest.raises(Empty):
            worker.get(block=False)
        worker.nack(processing)
    finally:
        worker.close()
    restarted = open_persistent_queue(path, auto_resume=False)
    try:
        assert restarted.get(block=False).markdown == "first"
    finally:
        restarted.close()


@pytest.mark.parametrize("source", ["http", "mcp"])
@pytest.mark.asyncio
async def test_submission_does_not_report_success_when_persistence_fails(monkeypatch, source):
    from unittest.mock import Mock

    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    queue = Mock()
    queue.put.side_effect = OSError("disk full")
    # Restore the actual producer after patch_context installs its lightweight fake.
    monkeypatch.setattr(findings, "enqueue_finding", REAL_ENQUEUE_FINDING)
    monkeypatch.setattr(findings, "get_persistent_queue", Mock(return_value=queue))
    with pytest.raises(OSError, match="disk full"):
        if source == "mcp":
            await findings.save_finding(None, "example.com", "body", "Title")
        else:
            await findings.save_finding_api(FakeRequest(
                "application/json", [json.dumps({"target": "example.com", "markdown": "body"}).encode()],
            ))
    queue.close.assert_called_once()
    assert ctx.task_queue.items == []


class RankedStore(Store):
    def __init__(self, docs, scores):
        super().__init__(docs)
        self.scores = scores
        self.rank_calls = []
        self.hydrated = []

    async def query_points(self, **kwargs):
        from types import SimpleNamespace

        assert kwargs["with_payload"] is False
        assert kwargs["with_vectors"] is False
        assert kwargs["search_params"].exact is True
        self.rank_calls.append(kwargs)
        ids = kwargs["query_filter"].must[0].has_id
        points = [qm.ScoredPoint(id=index, version=1, score=self.scores[index], payload=None)
                  for index in ids if kwargs["score_threshold"] is None
                  or self.scores[index] >= kwargs["score_threshold"]]
        points.sort(key=lambda point: -point.score)
        return SimpleNamespace(points=points[:kwargs["limit"]])

    async def retrieve(self, ids, **kwargs):
        self.hydrated.extend(ids)
        return await super().retrieve(ids, **kwargs)


def semantic_context(monkeypatch, store):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    ctx = ServerContext(store)
    ctx.finding_semantic_search = SimpleNamespace(prepare=AsyncMock(), embed=AsyncMock(return_value=[1.0, 0.0]))
    patch_context(monkeypatch, ctx)
    return ctx


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["example.com", "site:example.com", " site:example.com \n\t "])
async def test_no_semantic_text_ignores_semantic_ranges(monkeypatch, query):
    ctx = semantic_context(monkeypatch, RankedStore([finding_doc()], [0.9]))
    ctx.low_power = True
    result = await findings.query_findings(None, query,
                                          score_threshold=float("inf"))
    assert len(result.findings) == 1
    assert result.query == query
    assert result.findings[0].score is None
    ctx.finding_semantic_search.embed.assert_not_called()
    assert not ctx.qdrant_client.rank_calls
    ctx.finding_semantic_search.prepare.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs, message", [
    ({"score_threshold": -1.1}, "score_threshold"),
    ({"score_threshold": 1.1}, "score_threshold"),
    ({"score_threshold": float("nan")}, "score_threshold"),
    ({"score_threshold": float("inf")}, "score_threshold"),
])
async def test_semantic_validation(monkeypatch, kwargs, message):
    from mcp.server.mcpserver.exceptions import ToolError

    ctx = semantic_context(monkeypatch, RankedStore([], []))
    with pytest.raises(ToolError, match=message):
        await findings.query_findings(None, "site:example.com sessions", **kwargs)
    ctx.finding_semantic_search.embed.assert_not_called()


@pytest.mark.asyncio
async def test_semantic_ranking_cap_pages_progress(monkeypatch):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    store = RankedStore([finding_doc(title=str(i)) for i in range(1002)], [i / 1002 for i in range(1002)])
    ctx = semantic_context(monkeypatch, store)
    messages = []

    async def progress(_ctx, message):
        messages.append(message)

    monkeypatch.setattr(findings, "report_progress", progress)
    result = await findings.query_findings(None, " site:example.com sessions ", limit=500)
    assert result.query == " site:example.com sessions "
    assert result.findings[0].title == "1001"
    assert result.findings[0].score == 1001 / 1002
    assert result.pagination.total_items == 1000
    assert result.pagination.retrieval_truncated
    assert store.hydrated == list(range(1001, 1, -1))
    second = await get_result_page(None, result.pagination.next_page_token)
    assert second.result.findings[0].title == "501"
    assert second.result.pagination.next_page_token is None
    ctx.finding_semantic_search.embed.assert_awaited_once_with("sessions")
    assert messages == ["Finding saved findings within scope", "Scope matched 1002 findings",
                        "Preparing semantic search", "Embedding search query", "Ranking scoped findings",
                        "Loading 1000 matching findings"]


@pytest.mark.asyncio
@pytest.mark.parametrize("threshold, expected", [(None, 3), (-1, 3), (0.6, 1), (1, 0)])
async def test_semantic_threshold_default_cap_and_scope(monkeypatch, threshold, expected):
    store = RankedStore([
        finding_doc(title="url"), finding_doc(url="", host="api.example.com", title="host"),
        finding_doc(title="other", url="https://elsewhere.target.local/", host="elsewhere.target.local"),
        finding_doc(title="low"),
    ], [0.8, 0.5, 0.99, -0.5])
    semantic_context(monkeypatch, store)
    result = await findings.query_findings(None, "site:example.com sessions", score_threshold=threshold)
    assert len(result.findings) == expected
    assert store.rank_calls[0]["limit"] == 1001
    assert 2 not in store.rank_calls[0]["query_filter"].must[0].has_id
    assert not result.retrieval_truncated


@pytest.mark.asyncio
async def test_semantic_exact_predicate_verification_before_ranking(monkeypatch):
    store = RankedStore([finding_doc(url="https://example.com/abc--bcd"),
                         finding_doc(url="https://example.com/abcd"),
                         finding_doc(url="https://example.com/abcd.js")], [0.99, 0.8, 1.0])
    semantic_context(monkeypatch, store)
    result = await findings.query_findings(None, "site:example.com inurl:abcd -ext:js sessions")
    assert store.rank_calls[0]["query_filter"].must[0].has_id == [1]
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_semantic_empty_scope_and_low_power(monkeypatch):
    ctx = semantic_context(monkeypatch, RankedStore([], []))
    result = await findings.query_findings(None, "site:example.com sessions")
    assert not result.findings
    ctx.finding_semantic_search.embed.assert_not_called()
    ctx.low_power = True
    result = await findings.query_findings(None, "site:example.com sessions")
    assert "low-power" in result.instructions
    ctx.finding_semantic_search.embed.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["prepare", "embed", "rank", "hydrate"])
async def test_semantic_failures_are_not_unranked_fallbacks(monkeypatch, operation):
    from unittest.mock import AsyncMock

    store = RankedStore([finding_doc()], [0.9])
    ctx = semantic_context(monkeypatch, store)
    target, name = {"prepare": (ctx.finding_semantic_search, "prepare"), "embed": (ctx.finding_semantic_search, "embed"),
                    "rank": (store, "query_points"), "hydrate": (store, "retrieve")}[operation]
    monkeypatch.setattr(target, name, AsyncMock(side_effect=RuntimeError("unavailable")))
    with pytest.raises(RuntimeError, match="unavailable"):
        await findings.query_findings(None, "site:example.com sessions")


@pytest.mark.asyncio
async def test_progress_failure_does_not_fail_search(monkeypatch):
    from unittest.mock import AsyncMock

    semantic_context(monkeypatch, RankedStore([finding_doc()], [0.9]))
    monkeypatch.setattr(findings, "report_progress", AsyncMock(side_effect=RuntimeError("disconnected")))
    result = await findings.query_findings(None, "site:example.com sessions")
    assert len(result.findings) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_semantic_protocol_and_lenient_validation(monkeypatch, mode):
    from mcp.client import Client
    from mcp.server import MCPServer

    semantic_context(monkeypatch, RankedStore([finding_doc()], [0.9]))
    server = MCPServer("semantic-finding-test")
    server.add_tool(findings.query_findings)
    async with Client(server, mode=mode) as client:
        for query in ["example.com", "site:example.com", "site:example.com sessions"]:
            args = {"query": query, "score_threshold": 5}
            result = await client.call_tool("query_findings", args)
            if query == "site:example.com sessions":
                assert result.is_error
            else:
                assert not result.is_error
                assert result.structured_content["query"] == query
        result = await client.call_tool("query_findings", {"query": "site:example.com sessions"})
        assert not result.is_error
        assert result.structured_content["findings"][0]["score"] == 0.9


@pytest.mark.asyncio
async def test_semantic_ties_have_stable_id_order(monkeypatch):
    store = RankedStore([finding_doc(title="first"), finding_doc(title="second")], [0.5, 0.5])
    semantic_context(monkeypatch, store)
    result = await findings.query_findings(None, "site:example.com sessions")
    assert [item.title for item in result.findings] == ["first", "second"]


@pytest.mark.asyncio
async def test_deleted_record_does_not_shift_remaining_scores(monkeypatch):
    store = RankedStore([finding_doc(title="first"), finding_doc(title="second")], [0.9, 0.8])
    semantic_context(monkeypatch, store)
    original = store.retrieve

    async def retrieve(ids, **kwargs):
        return await original(ids=[point_id for point_id in ids if point_id != 0], **kwargs)

    monkeypatch.setattr(store, "retrieve", retrieve)
    result = await findings.query_findings(None, "site:example.com sessions")
    assert len(result.findings) == 1
    assert result.findings[0].title == "second"
    assert result.findings[0].score == 0.8


@pytest.mark.asyncio
async def test_tool_progress_counters_are_monotonic_and_reset(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    semantic_context(monkeypatch, RankedStore([finding_doc()], [0.9]))
    ctx = SimpleNamespace(report_progress=AsyncMock())
    for _ in range(2):
        ctx.report_progress.reset_mock()
        await findings.query_findings(ctx, "site:example.com sessions")
        assert [call.args[0] for call in ctx.report_progress.await_args_list] == list(range(1, 7))
        assert ctx.report_progress.await_args_list[-1].kwargs["message"] == "Loading 1 matching findings"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_unified_query_schema_and_missing_scope(monkeypatch, mode):
    from mcp.client import Client
    from mcp.server import MCPServer

    semantic_context(monkeypatch, RankedStore([finding_doc()], [0.9]))
    server = MCPServer("unified-finding-test")
    server.add_tool(findings.query_findings)
    async with Client(server, mode=mode) as client:
        catalog = await client.list_tools()
        tool = next(tool for tool in catalog.tools if tool.name == "query_findings")
        assert "query" in tool.input_schema["required"]
        assert "target" not in tool.input_schema["properties"]
        assert "retrieval_limit" not in tool.input_schema["properties"]
        assert "target" not in tool.output_schema["properties"]
        old_call = await client.call_tool("query_findings", {"target": "example.com"})
        assert old_call.is_error
        for query in ["", "  ", "authentication bypass", "inurl:admin sessions"]:
            result = await client.call_tool("query_findings", {"query": query})
            assert "Invalid finding query" in result.structured_content["instructions"]
        result = await client.call_tool("query_findings", {"query": "site:example.com sessions"})
        assert "target" not in result.structured_content
        assert result.structured_content["findings"][0]["target"] == "https://example.com/a"


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [999, 1000, 1001])
async def test_fixed_semantic_cap_instructions_and_truncation(monkeypatch, count):
    store = RankedStore([finding_doc(title=str(i)) for i in range(count)], [0.8] * count)
    semantic_context(monkeypatch, store)
    result = await findings.query_findings(None, "site:example.com sessions", limit=1000)
    assert len(result.findings) == min(count, 1000)
    assert result.retrieval_truncated == (count > 1000)
    assert ("Narrow the search" in result.instructions) == (count >= 1000)
    assert ("1000-finding limit" in result.instructions) == (count >= 1000)
    assert len(store.hydrated) == min(count, 1000)


@pytest.mark.asyncio
async def test_predicate_only_retrieval_is_not_subject_to_semantic_cap(monkeypatch):
    store = RankedStore([finding_doc(title=str(i)) for i in range(1001)], [0.8] * 1001)
    ctx = semantic_context(monkeypatch, store)
    result = await findings.query_findings(None, "site:example.com", limit=1000)
    assert result.pagination.total_items == 1001
    assert not result.retrieval_truncated
    assert "1000-finding limit" not in result.instructions
    ctx.finding_semantic_search.prepare.assert_not_called()


@pytest.mark.parametrize("content_type", ["application/json", "application/x-www-form-urlencoded"])
async def test_metadata_round_trips_and_affected_method_is_not_submission_method(monkeypatch, content_type):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    payload = {"target": "https://example.com/search", "markdown": "issue", "metadata": {
        "source": "zap", "affected_method": "get", "parameter": {"name": "q", "location": "query"},
        "cwe_ids": ["CWE-79"], "severity": "medium", "confidence": "high",
    }}
    if content_type == "application/json":
        request = FakeRequest(content_type, [json.dumps(payload).encode()])
    else:
        request = FakeRequest(content_type, form_data={**payload, "metadata": json.dumps(payload["metadata"])})
    response = await findings.save_finding_api(request)
    assert response.status_code == 201
    assert ctx.finding_queue.items[0].metadata["affected_method"] == "GET"
    assert "verification_status" not in ctx.finding_queue.items[0].metadata
    await findings.save_finding(None, payload["target"], "second", "Title", findings.FindingMetadata(source="burp"))
    assert ctx.finding_queue.items[1].metadata == {"source": "burp"}


@pytest.mark.parametrize("record", [
    {"target": "example.com", "markdown": "issue", "metadata": {"severity": "bad"}},
    {"target": "example.com", "markdown": "issue", "metadata": {"affected_method": "GET /"}},
    {"targets": ["example.com", "not a target"], "markdown": "issue"},
    [], None, {"target": "example.com", "markdown": ""},
])
async def test_all_records_validated_before_any_queue_write(monkeypatch, record):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    content = json.dumps({"target": "example.com", "markdown": "valid"}) + "\n" + json.dumps(record)
    response = await findings.save_finding_api(FakeRequest("application/json", [content.encode()]))
    assert response.status_code == 400
    assert not ctx.finding_queue.items
    assert json.loads(response.body)["errors"][0]["field"]


async def test_empty_invalid_utf8_and_invalid_form_metadata(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    for request in [FakeRequest("application/json"), FakeRequest("application/json", [b"\xff"]),
                    FakeRequest("application/x-www-form-urlencoded", form_data={"metadata": "{"})]:
        assert (await findings.save_finding_api(request)).status_code == 400


async def test_query_exposes_stable_finding_ids_and_structured_fields(monkeypatch):
    doc = finding_doc()
    doc.meta["finding_metadata"] = {"source": "burp", "severity": "high"}
    patch_context(monkeypatch, ServerContext(Store([doc])))
    result = await findings.query_findings(None, "example.com")
    assert result.findings[0].finding_id
    assert result.findings[0].metadata == {"source": "burp", "severity": "high"}
