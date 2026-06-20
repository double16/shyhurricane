import pytest
from haystack import Document
from shyhurricane.task_queue.types import SpiderResultItem

import shyhurricane.mcp_server.tools.find_web_resources as resources


def make_doc(doc_id, url, content="body", score=1.0, **meta):
    base_meta = {
        "url": url,
        "type": "content",
        "host": "example.com",
        "domain": "example.com",
        "netloc": "example.com:443",
        "port": 443,
        "http_method": "GET",
        "status_code": 200,
        "content_type": "text/html",
        "response_headers": "{}",
    }
    base_meta.update(meta)
    return Document(id=doc_id, content=content, score=score, meta=base_meta)


class AsyncStore:
    def __init__(self, responses):
        self.responses = list(responses)
        self.filters = []

    async def filter_documents_async(self, filters):
        self.filters.append(filters)
        return self.responses.pop(0)


class ServerContext:
    def __init__(self, store):
        self.stores = {"content": store}
        self.document_pipeline = None
        self.website_context_pipeline = None
        self.open_world = True
        self.disable_elicitation = False


async def noop(*args, **kwargs):
    return None


def patch_server_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(resources, "get_server_context", get_fake_server_context)


def test_append_in_filter_skips_none_and_uses_equality_or_in():
    conditions = []

    resources._append_in_filter(conditions, "meta.host", [None])
    resources._append_in_filter(conditions, "meta.host", ["a.test"])
    resources._append_in_filter(conditions, "meta.port", [80, 443])

    assert conditions == [
        {"field": "meta.host", "operator": "==", "value": "a.test"},
        {"field": "meta.port", "operator": "in", "value": [80, 443]},
    ]


def test_documents_to_http_resources_creates_resource_link_when_content_present():
    docs = [
        make_doc("doc-1", "https://example.com/", content="hello", title="Home"),
        Document(id="doc-2", content="", meta={"url": "https://example.com/empty", "type": "content"}),
    ]

    result = resources._documents_to_http_resources(docs)

    assert result[0].url == "https://example.com/"
    assert str(result[0].resource.uri) == "web://content/doc-1"
    assert result[0].resource.size == 5
    assert result[1].resource is None


@pytest.mark.asyncio
async def test_find_web_resources_by_url_returns_exact_and_child_resources(monkeypatch):
    exact = make_doc("exact", "https://example.com/app")
    child = make_doc("child", "https://example.com/app/settings")
    duplicate = make_doc("dupe", "https://example.com/app")
    store = AsyncStore([[exact], [child, duplicate]])
    patch_server_context(monkeypatch, ServerContext(store))

    result = await resources._find_web_resources_by_url(None, "https://example.com/app", limit=10)

    assert [item.url for item in result] == ["https://example.com/app", "https://example.com/app/settings"]
    assert store.filters[0]["conditions"][1]["field"] == "meta.url"
    assert store.filters[1]["conditions"][1]["field"] == "meta.netloc"


@pytest.mark.asyncio
async def test_find_web_resources_by_netloc_and_hostname(monkeypatch):
    netloc_doc = make_doc("netloc", "https://example.com/")
    host_doc = make_doc("host", "https://example.com/about")
    store = AsyncStore([[netloc_doc], [host_doc]])
    patch_server_context(monkeypatch, ServerContext(store))

    netloc_result = await resources._find_web_resources_by_netloc(None, "example.com:443", limit=10)
    host_result = await resources._find_web_resources_by_hostname(None, "example.com", limit=10)

    assert [item.url for item in netloc_result] == ["https://example.com/"]
    assert [item.url for item in host_result] == ["https://example.com/about"]


@pytest.mark.asyncio
async def test_find_web_resources_by_netloc_rejects_invalid_queries(monkeypatch):
    store = AsyncStore([])
    patch_server_context(monkeypatch, ServerContext(store))

    assert await resources._find_web_resources_by_netloc(None, "not a host", limit=10) is None
    assert await resources._find_web_resources_by_hostname(None, "example.com:443", limit=10) is None


def test_find_web_resources_result_and_spider_instructions():
    found = resources.find_web_resources_result(
        "query",
        ["GET"],
        10,
        resources._documents_to_http_resources([make_doc("doc", "https://example.com/")]),
    )
    missing = resources.find_web_resources_result("query", None, 10, [])

    assert found.instructions == resources.find_web_resources_instructions
    assert missing.instructions == resources.find_web_resources_instructions_not_found
    assert resources.spider_instructions([object()], True).endswith(resources.spider_results_instructions_has_more)
    assert resources.spider_instructions([], False) == resources.spider_results_instructions_not_found


@pytest.mark.asyncio
async def test_find_web_resources_low_power_returns_without_pipelines(monkeypatch):
    store = AsyncStore([[], [], []])
    patch_server_context(monkeypatch, ServerContext(store))
    monkeypatch.setattr(resources, "log_tool_history", noop)

    result = await resources.find_web_resources(None, "find things on invalid target", limit=1, http_methods="GET")

    assert result.instructions == resources.find_web_resources_instructions_low_power
    assert result.limit == 10
    assert result.http_methods == ["GET"]


class Record:
    def __init__(self, meta):
        self.payload = {"meta": meta}


async def scroll(records):
    for record in records:
        yield record


@pytest.mark.asyncio
async def test_is_spider_time_recent_returns_true_after_enough_recent_records(monkeypatch):
    now = 1_000_000.0
    records = [
        Record({"timestamp_float": now - 10, "url": "https://example.com/path/" + str(idx)})
        for idx in range(11)
    ]
    monkeypatch.setattr(resources.time, "time", lambda: now)
    monkeypatch.setattr(resources, "scroll_qdrant_collection", lambda **kwargs: scroll(records))

    assert await resources.is_spider_time_recent(type("Ctx", (), {"qdrant_client": object()})(),
                                                 "https://example.com/path") is True


@pytest.mark.asyncio
async def test_is_spider_time_recent_returns_false_for_old_bad_or_invalid_records(monkeypatch):
    now = 1_000_000.0
    records = [
        Record({"timestamp_float": now - 90_000, "url": "https://example.com/path/old"}),
        Record({"timestamp_float": "bad", "url": "https://example.com/path/bad"}),
    ]
    monkeypatch.setattr(resources.time, "time", lambda: now)
    monkeypatch.setattr(resources, "scroll_qdrant_collection", lambda **kwargs: scroll(records))

    assert await resources.is_spider_time_recent(type("Ctx", (), {"qdrant_client": object()})(),
                                                 "https://example.com/path") is False
    assert await resources.is_spider_time_recent(type("Ctx", (), {"qdrant_client": object()})(), "not a url") is False


class LifespanContext:
    app_context_id = "ctx-1"
    http_headers = {"X-Global": "yes"}
    cached_get_additional_hosts = {}


class RequestContext:
    lifespan_context = LifespanContext()


class ToolCtx:
    request_context = RequestContext()

    def __init__(self):
        self.messages = []
        self.elicit_result = None

    async def info(self, message):
        self.messages.append(message)

    async def elicit(self, message, schema):
        self.messages.append(message)
        return self.elicit_result


class Queue:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.put_items = []

    def put(self, item, block=True):
        self.put_items.append(item)

    def get(self, timeout):
        if not self.items:
            raise resources.queue.Empty
        return self.items.pop(0)


class SpiderServerContext:
    open_world = True
    qdrant_client = object()

    def __init__(self, results=None):
        self.task_queue = Queue()
        self.spider_result_queue = Queue(results)


@pytest.mark.asyncio
async def test_spider_website_returns_recent_indexed_results(monkeypatch):
    resource = resources._documents_to_http_resources([make_doc("doc", "https://example.com/")])[0]
    server_ctx = SpiderServerContext()

    async def get_server_context():
        return server_ctx

    async def is_recent(server_ctx, url):
        return True

    monkeypatch.setattr(resources, "log_tool_history", noop)
    monkeypatch.setattr(resources, "get_server_context", get_server_context)
    monkeypatch.setattr(resources, "is_spider_time_recent", is_recent)

    async def find_web_resources(ctx, url, limit):
        return resources.FindWebResourcesResult(
            instructions="",
            query=url,
            limit=limit,
            resources=[resource],
        )

    monkeypatch.setattr(resources, "find_web_resources", find_web_resources)

    result = await resources.spider_website(ToolCtx(), " https://example.com/ ", timeout_seconds=30)

    assert result.url == "https://example.com/"
    assert result.resources == [resource]
    assert result.has_more is False


@pytest.mark.asyncio
async def test_spider_website_queues_work_requeues_other_context_and_collects_results(monkeypatch):
    resource = resources._documents_to_http_resources([make_doc("doc", "https://example.com/found")])[0]
    other = SpiderResultItem("other", resource)
    done = SpiderResultItem("ctx-1", None)
    found = SpiderResultItem("ctx-1", resource)
    server_ctx = SpiderServerContext([other, found, done])

    async def get_server_context():
        return server_ctx

    async def is_recent(server_ctx, url):
        return False

    monkeypatch.setattr(resources, "log_tool_history", noop)
    monkeypatch.setattr(resources, "get_server_context", get_server_context)
    monkeypatch.setattr(resources, "is_spider_time_recent", is_recent)
    monkeypatch.setattr(resources, "get_rate_limit_requests_per_second", lambda url: 9)
    monkeypatch.setattr(resources, "get_additional_hosts", lambda ctx, additional=None: additional or {})

    ctx = ToolCtx()
    result = await resources.spider_website(
        ctx,
        "https://example.com",
        additional_hosts={"example.com": "127.0.0.1"},
        user_agent="agent",
        request_headers="X-Test: yes",
        cookies="sid=abc",
        timeout_seconds=30,
    )

    queued = server_ctx.task_queue.put_items[0]
    assert queued.uri == "https://example.com"
    assert queued.user_agent == "agent"
    assert queued.request_headers == {"X-Global": "yes", "X-Test": "yes"}
    assert queued.cookies == {"sid": "abc"}
    assert queued.rate_limit_requests_per_second == 9
    assert server_ctx.spider_result_queue.put_items[0].context_id == "other"
    assert result.resources == [resource]
    assert result.has_more is False
    assert ctx.messages == ["Found: https://example.com/found"]


class Pipeline:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, data=None, include_outputs_from=None):
        self.calls.append((data, include_outputs_from))
        if isinstance(self.result, list):
            return self.result.pop(0)
        return self.result


class FullServerContext(ServerContext):
    def __init__(self, store, website_context_result, document_result, open_world=True):
        super().__init__(store)
        if isinstance(website_context_result, list):
            self.website_context_pipeline = Pipeline(website_context_result)
        else:
            self.website_context_pipeline = Pipeline({"llm": {"replies": [website_context_result]}})
        self.document_pipeline = Pipeline(document_result)
        self.open_world = open_world


class Netlocs:
    def __init__(self, values):
        self.network_locations = values


@pytest.mark.asyncio
async def test_find_web_resources_runs_document_pipeline_with_target_filters(monkeypatch):
    doc = make_doc("doc", "https://example.com/admin", score=2.0, timestamp_float=10)
    store = AsyncStore([[], [], []])
    server_ctx = FullServerContext(
        store,
        '{"target": ["example.com"], "content": ["html"], "response_codes": [403]}',
        {"combine": {"documents": [doc]}},
    )
    patch_server_context(monkeypatch, server_ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    async def find_netloc(ctx, query):
        return Netlocs(["example.com:80", "example.com:443"])

    monkeypatch.setattr(resources, "find_netloc", find_netloc)

    result = await resources.find_web_resources(ToolCtx(), " find admin pages ", limit=12, http_methods=["POST"])

    data, include_outputs_from = server_ctx.document_pipeline.calls[0]
    filters = data["query"]["filters"]
    assert result.resources[0].url == "https://example.com/admin"
    assert include_outputs_from == {"combine"}
    assert data["query"]["targets"] == ["example.com:80", "example.com:443"]
    assert data["query"]["doc_types"] == ["html"]
    assert {"field": "meta.http_method", "operator": "==", "value": "POST"} in filters["conditions"]
    assert {"field": "meta.status_code", "operator": "==", "value": 403} in filters["conditions"]


@pytest.mark.asyncio
async def test_find_web_resources_uses_recommended_urls_and_domain_filter(monkeypatch):
    doc = make_doc("doc", "https://sub.example.com/", domain="example.com", netloc="sub.example.com:443")
    server_ctx = FullServerContext(
        AsyncStore([[], [], []]),
        '{"target": [], "content": [], "response_codes": []}',
        {"combine": {"documents": [doc]}},
    )
    patch_server_context(monkeypatch, server_ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    async def recommended(ctx):
        return ["sub.example.com"]

    async def find_netloc(ctx, query):
        return Netlocs(["known.sub.example.com:443"])

    monkeypatch.setattr(resources, "_find_recommended_urls", recommended)
    monkeypatch.setattr(resources, "find_netloc", find_netloc)

    result = await resources.find_web_resources(ToolCtx(), "no explicit target", limit=10)

    filters = server_ctx.document_pipeline.calls[0][0]["query"]["filters"]
    assert result.resources[0].url == "https://sub.example.com/"
    assert {"field": "meta.domain", "operator": "==", "value": "sub.example.com"} in filters["conditions"]


@pytest.mark.asyncio
async def test_find_web_resources_elicits_missing_target_and_handles_decline(monkeypatch):
    server_ctx = FullServerContext(
        AsyncStore([[], [], []]),
        [
            {"llm": {"replies": [""]}},
            {"llm": {"replies": ['{"target": ["example.com"], "content": [], "response_codes": []}']}},
        ],
        {"combine": {"documents": []}},
    )
    patch_server_context(monkeypatch, server_ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)
    monkeypatch.setattr(resources, "assert_elicitation", lambda server_ctx: None)

    async def no_recommended(ctx):
        return None

    async def find_netloc(ctx, query):
        return Netlocs(["example.com:80", "example.com:443"])

    monkeypatch.setattr(resources, "_find_recommended_urls", no_recommended)
    monkeypatch.setattr(resources, "find_netloc", find_netloc)

    ctx = ToolCtx()
    ctx.elicit_result = resources.AcceptedElicitation(data=resources.RequestTargetUrl(data="example.com"))

    result = await resources.find_web_resources(ctx, "what is indexed?", limit=10)

    assert result.instructions == resources.find_web_resources_instructions_not_found
    assert "What URL(s) should we look for?" in ctx.messages


@pytest.mark.asyncio
async def test_find_web_resources_missing_target_open_world_branches(monkeypatch):
    server_ctx = FullServerContext(
        AsyncStore([[], [], []]),
        '{"target": ["missing.example.com"], "content": [], "response_codes": []}',
        {"combine": {"documents": []}},
        open_world=False,
    )
    patch_server_context(monkeypatch, server_ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    async def find_netloc(ctx, query):
        return Netlocs(["other.example.com:443"])

    monkeypatch.setattr(resources, "find_netloc", find_netloc)

    result = await resources.find_web_resources(ToolCtx(), "missing.example.com", limit=10)

    assert result.instructions == resources.find_web_resources_instructions_not_found


@pytest.mark.asyncio
async def test_find_web_resources_starts_spider_when_elicitation_unavailable(monkeypatch):
    server_ctx = FullServerContext(
        AsyncStore([[], [], []]),
        '{"target": ["missing.example.com"], "content": [], "response_codes": []}',
        {"combine": {"documents": []}},
    )
    patch_server_context(monkeypatch, server_ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    async def find_netloc(ctx, query):
        return Netlocs([])

    def raise_mcp_error(server_ctx):
        from mcp.types import ErrorData, INTERNAL_ERROR
        raise resources.McpError(ErrorData(code=INTERNAL_ERROR, message="nope"))

    monkeypatch.setattr(resources, "find_netloc", find_netloc)
    monkeypatch.setattr(resources, "assert_elicitation", raise_mcp_error)
    spidered = []

    async def spider_website(ctx, url):
        spidered.append(url)

    monkeypatch.setattr(resources, "spider_website", spider_website)

    await resources.find_web_resources(ToolCtx(), "missing.example.com", limit=10)

    assert spidered == ["http://missing.example.com:80", "https://missing.example.com:443"]
