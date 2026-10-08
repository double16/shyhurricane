import asyncio
from types import SimpleNamespace

import pytest
from haystack import Document

import shyhurricane.mcp_server.tools.find_web_resources as resources
from shyhurricane import predicate_search
from shyhurricane.mcp_server.progress import progress_scope, report_progress
from shyhurricane.task_queue.types import SpiderResultItem


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


@pytest.mark.asyncio
async def test_find_web_resources_exact_queries_return_none_when_store_is_empty(monkeypatch):
    store = AsyncStore([[], [], [], []])
    patch_server_context(monkeypatch, ServerContext(store))

    assert await resources._find_web_resources_by_url(None, "https://example.com/", limit=10) is None
    assert await resources._find_web_resources_by_netloc(None, "example.com:443", limit=10) is None
    assert await resources._find_web_resources_by_hostname(None, "example.com", limit=10) is None


@pytest.mark.asyncio
async def test_recommended_urls_require_one_domain_and_choose_scheme_from_port(monkeypatch):
    class NetlocResult:
        def __init__(self, locations):
            self.network_locations = locations

    async def netlocs(ctx, query):
        return NetlocResult([])

    monkeypatch.setattr(resources, "find_netloc", netlocs)
    assert await resources._find_recommended_urls(None) is None

    async def mixed_domains(ctx, query):
        return NetlocResult(["example.com:443", "other.test:80"])

    monkeypatch.setattr(resources, "find_netloc", mixed_domains)
    assert await resources._find_recommended_urls(None) is None

    async def one_domain(ctx, query):
        return NetlocResult(["www.example.com:443", "api.example.com:8080"])

    monkeypatch.setattr(resources, "find_netloc", one_domain)
    assert await resources._find_recommended_urls(None) == [
        "https://www.example.com:443", "http://api.example.com:8080"
    ]


def test_find_web_resources_result_and_spider_instructions():
    found = resources.find_web_resources_result(
        "query",
        ["GET"],
        10,
        resources._documents_to_http_resources([make_doc("doc", "https://example.com/")]),
    )
    missing = resources.find_web_resources_result("query", None, 10, [])

    assert found.instructions == resources.find_web_resources_instructions
    assert missing.instructions == resources.find_web_resources_instructions_no_matches
    unindexed = resources.find_web_resources_result("query", None, 10, [], target_indexed=False)
    assert unindexed.instructions == resources.find_web_resources_instructions_not_found
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


@pytest.mark.asyncio
async def test_find_web_resources_low_power_flag_disables_retrieval_when_pipelines_present(monkeypatch):
    store = AsyncStore([[], [], []])
    ctx = ServerContext(store)
    ctx.document_pipeline = object()
    ctx.website_context_pipeline = object()
    ctx.low_power = True
    patch_server_context(monkeypatch, ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    result = await resources.find_web_resources(None, "find things on invalid target", limit=1, http_methods="GET")

    assert result.instructions == resources.find_web_resources_instructions_low_power
    assert result.limit == 10
    assert result.http_methods == ["GET"]


@pytest.mark.asyncio
async def test_find_web_resources_calls_ensure_retrieval_pipelines_when_not_low_power(monkeypatch):
    store = AsyncStore([[], [], []])
    ctx = ServerContext(store)
    ctx.low_power = False
    pipeline_ensured = False

    async def ensure_pipelines():
        nonlocal pipeline_ensured
        pipeline_ensured = True

    ctx.ensure_retrieval_pipelines = ensure_pipelines
    patch_server_context(monkeypatch, ctx)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    result = await resources.find_web_resources(None, "find things on invalid target", limit=1, http_methods="GET")

    assert pipeline_ensured is True
    assert result.instructions == resources.find_web_resources_instructions_low_power


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
        self.progress = []
        self.elicit_result = None

    async def report_progress(self, progress, total=None, message=None):
        self.messages.append(message)
        self.progress.append((progress, total, message))

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
    assert ctx.progress == [(1, None, "Found: https://example.com/found")]


class Pipeline:
    async def run_async(self, data=None, include_outputs_from=None):
        return self.run(data, include_outputs_from)

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


@pytest.fixture
def predicate_context(monkeypatch):
    from qdrant_client.local.payload_filters import check_filter

    docs = [
        make_doc("body", "https://example.com/app.js", timestamp="t", timestamp_float=2,
                 version=resources.WEB_RESOURCE_VERSION, content_type="application/javascript"),
        make_doc("sub", "https://sub.example.com:9443/admin.js", timestamp="t", timestamp_float=3,
                 version=resources.WEB_RESOURCE_VERSION, content_type="application/javascript",
                 netloc="sub.example.com:9443", host="sub.example.com", port=9443, status_code=403),
        make_doc("other", "https://otherexample.com/app.js", timestamp="t", timestamp_float=4,
                 version=resources.WEB_RESOURCE_VERSION, netloc="otherexample.com:443", host="otherexample.com",
                 domain="otherexample.com"),
        make_doc("headers", "https://example.com/app.js", timestamp="t", timestamp_float=2,
                 version=resources.WEB_RESOURCE_VERSION, type="network", content_type="text/plain",
                 response_headers='{"Content-Type":"application/javascript"}'),
    ]
    points = {
        "content": [
            SimpleNamespace(id=index, payload=doc.to_dict(flatten=False)) for index, doc in enumerate(docs[:3])
        ],
        "network": [SimpleNamespace(id=3, payload=docs[3].to_dict(flatten=False))],
    }

    class Client:
        async def get_collections(self):
            return SimpleNamespace(collections=[SimpleNamespace(name=name) for name in points])

        async def retrieve(self, collection_name, ids, **kwargs):
            return [point for point in points[collection_name] if point.id in ids]

    scopes = []

    async def scroll(client, collection, fields, scroll_filter):
        scopes.append(scroll_filter)
        for point in points[collection]:
            if check_filter(scroll_filter, point.payload, point.id, {}):
                yield point

    async def netlocs(ctx, query):
        return Netlocs(["example.com:443", "sub.example.com:9443", "otherexample.com:443"])

    server_ctx = FullServerContext(
        AsyncStore([]), '{"target": ["unrelated.test"], "content": ["network"], "response_codes": [500]}',
        {"combine": {"documents": [docs[1]]}},
    )
    server_ctx.low_power = False
    server_ctx.qdrant_client = Client()
    server_ctx.ensure_retrieval_pipelines = noop
    monkeypatch.setattr(predicate_search, "scroll_qdrant_collection", scroll)
    monkeypatch.setattr(resources, "find_netloc", netlocs)
    monkeypatch.setattr(resources, "log_tool_history", noop)
    monkeypatch.setattr(resources, "report_progress", noop)
    patch_server_context(monkeypatch, server_ctx)
    return server_ctx, scopes


@pytest.mark.asyncio
@pytest.mark.parametrize("low_power", [False, True])
async def test_predicate_only_search_needs_no_llm_and_includes_nonstandard_ports(predicate_context, low_power):
    server_ctx, scopes = predicate_context
    server_ctx.low_power = low_power
    server_ctx.ensure_retrieval_pipelines = None
    result = await resources.find_web_resources(ToolCtx(), "site:example.com ext:js -inurl:admin")
    assert [resource.url for resource in result.resources] == ["https://example.com/app.js"]
    assert result.resources[0].resource.uri == "web://content/body"
    assert result.query == "site:example.com ext:js -inurl:admin"
    assert server_ctx.website_context_pipeline.calls == []
    assert server_ctx.document_pipeline.calls == []
    assert scopes[0].must[1].match.any == ["example.com:443", "sub.example.com:9443"]


@pytest.mark.asyncio
async def test_predicate_search_applies_status_mime_type_and_methods(predicate_context):
    result = await resources.find_web_resources(
        ToolCtx(), "site:example.com status:200 mime:application/javascript type:network method:get",
        http_methods="GET",
    )
    assert len(result.resources) == 1
    assert str(result.resources[0].resource.uri) == "web://network/headers"
    conflict = await resources.find_web_resources(ToolCtx(), "site:example.com method:POST", http_methods=["GET"])
    assert conflict.resources == []
    excluded = await resources.find_web_resources(ToolCtx(), "site:example.com -site:sub.example.com -status:200")
    assert excluded.resources == []


@pytest.mark.asyncio
async def test_mixed_predicates_override_inferred_target_status_and_use_residual_query(predicate_context):
    server_ctx, _ = predicate_context
    result = await resources.find_web_resources(ToolCtx(), "site:example.com status:403 unsafe eval calls")
    assert result.resources[0].url == "https://sub.example.com:9443/admin.js"
    data, _ = server_ctx.document_pipeline.calls[0]
    assert data["query"]["text"] == "unsafe eval calls"
    native = data["query"]["filters"]["predicate_filters"]
    assert native["content"].must[0].has_id == [1]
    assert native["network"].must[0].has_id == []
    assert data["query"]["targets"] == ["example.com:443", "sub.example.com:9443"]
    assert server_ctx.website_context_pipeline.calls[0][0]["builder"]["query"] == "unsafe eval calls"


@pytest.mark.asyncio
async def test_predicates_eliminating_candidates_do_not_scan_or_rank(predicate_context):
    server_ctx, _ = predicate_context
    result = await resources.find_web_resources(ToolCtx(), "site:example.com status:404 missing pages")
    assert result.resources == []
    assert result.instructions == resources.find_web_resources_instructions_no_matches
    assert server_ctx.document_pipeline.calls == []
    result = await resources.find_web_resources(ToolCtx(), "site:example.com site:otherexample.com")
    assert result.resources == []
    assert result.instructions == resources.find_web_resources_instructions_no_matches


@pytest.mark.asyncio
async def test_semantic_search_with_existing_target_and_no_matches(predicate_context):
    server_ctx, _ = predicate_context
    server_ctx.stores["content"] = AsyncStore([[], [], []])
    server_ctx.website_context_pipeline = Pipeline({"llm": {"replies": ['{"target": ["https://example.com"]}']}})
    server_ctx.document_pipeline = Pipeline({"combine": {"documents": []}})
    result = await resources.find_web_resources(ToolCtx(), "find nonexistent vulnerabilities on example.com")
    assert result.resources == []
    assert result.instructions == resources.find_web_resources_instructions_no_matches
    assert "populate" not in result.instructions


@pytest.mark.asyncio
async def test_partially_indexed_targets_are_searched_when_scan_is_unavailable(predicate_context):
    server_ctx, _ = predicate_context
    server_ctx.disable_elicitation = True
    server_ctx.stores["content"] = AsyncStore([[], [], []])
    server_ctx.website_context_pipeline = Pipeline({"llm": {"replies": [
        '{"target": ["https://example.com", "https://missing.test"]}',
    ]}})
    server_ctx.document_pipeline = Pipeline({"combine": {"documents": []}})
    result = await resources.find_web_resources(ToolCtx(), "find vulnerabilities on example.com and missing.test")
    assert result.instructions == resources.find_web_resources_instructions_no_matches
    assert len(server_ctx.document_pipeline.calls) == 1


@pytest.mark.asyncio
async def test_predicate_only_no_matches_on_indexed_target(predicate_context):
    result = await resources.find_web_resources(ToolCtx(), "site:example.com status:404")
    assert result.resources == []
    assert result.instructions == resources.find_web_resources_instructions_no_matches


@pytest.mark.asyncio
async def test_predicate_missing_target_does_not_scan_without_confirmation(predicate_context):
    server_ctx, _ = predicate_context
    server_ctx.disable_elicitation = True
    result = await resources.find_web_resources(ToolCtx(), "site:missing.example.com")
    assert result.resources == []
    assert result.instructions == resources.find_web_resources_instructions_not_found


@pytest.mark.asyncio
async def test_mixed_predicates_low_power_and_missing_pipelines(predicate_context):
    server_ctx, _ = predicate_context
    server_ctx.low_power = True
    result = await resources.find_web_resources(ToolCtx(), "site:example.com unsafe calls")
    assert result.instructions == resources.find_web_resources_instructions_low_power
    server_ctx.low_power = False
    server_ctx.document_pipeline = None
    result = await resources.find_web_resources(ToolCtx(), "site:example.com unsafe calls")
    assert result.instructions == resources.find_web_resources_instructions_low_power


@pytest.mark.asyncio
async def test_predicates_without_site_keep_target_recommendation_and_elicitation(predicate_context, monkeypatch):
    server_ctx, _ = predicate_context

    async def recommended(ctx):
        return ["https://example.com:443"]

    monkeypatch.setattr(resources, "_find_recommended_urls", recommended)
    result = await resources.find_web_resources(ToolCtx(), "ext:js")
    assert [resource.url for resource in result.resources] == ["https://example.com/app.js"]

    async def no_recommendation(ctx):
        return []

    monkeypatch.setattr(resources, "_find_recommended_urls", no_recommendation)
    server_ctx.disable_elicitation = True
    result = await resources.find_web_resources(ToolCtx(), "-site:example.com")
    assert result.instructions == resources.find_web_resources_instructions_need_target


@pytest.mark.asyncio
async def test_predicate_only_elicited_target_is_parsed_without_llm(predicate_context):
    from mcp.server.elicitation import AcceptedElicitation

    server_ctx, _ = predicate_context
    server_ctx.low_power = True
    server_ctx.website_context_pipeline = None
    search = resources.SearchPreparation(
        "ext:js", 10, None, server_ctx, predicates=[resources.Predicate("filetype", "js")], semantic_query="",
    )
    prepared = await resources._prepare_targets(
        ToolCtx(), search, AcceptedElicitation(data=resources.RequestTargetUrl(data="https://example.com:443")),
    )
    assert prepared.targets == ["https://example.com:443"]
    assert prepared.filter_netloc == ["example.com:443"]


@pytest.mark.asyncio
async def test_predicate_ipv6_site_resolution_and_missing_scan_url(predicate_context, monkeypatch):
    from mcp.server.elicitation import DeclinedElicitation

    server_ctx, _ = predicate_context

    async def netlocs(ctx, query):
        return Netlocs(["::1:8080"])

    monkeypatch.setattr(resources, "find_netloc", netlocs)
    search = resources.SearchPreparation(
        "site:[::1]:8080", 10, None, server_ctx, targets=["[::1]:8080"],
        predicates=[resources.Predicate("site", "[::1]:8080")], semantic_query="",
    )
    prepared = await resources._prepare_targets(ToolCtx(), search, DeclinedElicitation())
    assert prepared.filter_netloc == ["::1:8080"]

    async def empty(ctx, query):
        return Netlocs([])

    monkeypatch.setattr(resources, "find_netloc", empty)
    prepared = await resources._prepare_targets(ToolCtx(), search, DeclinedElicitation())
    assert prepared.missing_targets[0].to_url() == "http://[::1]:8080"


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

    assert result.instructions == resources.find_web_resources_instructions_no_matches
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
async def test_find_web_resources_does_not_spider_when_elicitation_unavailable(monkeypatch):
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
        from mcp.types import INTERNAL_ERROR
        raise resources.MCPError(INTERNAL_ERROR, "nope")

    monkeypatch.setattr(resources, "find_netloc", find_netloc)
    monkeypatch.setattr(resources, "assert_elicitation", raise_mcp_error)
    spidered = []

    async def spider_website(ctx, url):
        spidered.append(url)

    monkeypatch.setattr(resources, "spider_website", spider_website)

    await resources.find_web_resources(ToolCtx(), "missing.example.com", limit=10)

    assert spidered == []


@pytest.mark.asyncio
@pytest.mark.parametrize("notification_fails", [False, True])
async def test_search_threaded_progress_after_nested_scan(monkeypatch, caplog, notification_fails):
    ctx = ToolCtx()
    loop = asyncio.get_running_loop()
    original_report = ctx.report_progress

    async def send(progress, total=None, message=None):
        assert asyncio.get_running_loop() is loop
        if notification_fails and message == "Querying content":
            raise RuntimeError("notification failed")
        await original_report(progress, total, message)

    ctx.report_progress = send

    class DocumentPipeline:
        def run(self, data, **kwargs):
            data["query"]["progress_callback"]("Querying content")
            return {"combine": {"documents": []}}

    search = resources.SearchPreparation(
        query="example.com", limit=10, http_methods=None,
        server_ctx=SimpleNamespace(open_world=True, document_pipeline=DocumentPipeline()),
        targets=["example.com"], missing_targets=[resources.TargetInfo(hostname="example.com")],
    )

    @progress_scope()
    async def scan(*args):
        await report_progress(ctx, "Found: https://example.com/")

    monkeypatch.setattr(resources, "spider_website", scan)
    monkeypatch.setattr(resources, "log_tool_history", noop)

    @progress_scope()
    async def request():
        await resources._determine_targets(
            ctx,
            resources.SearchPreparation(
                query="", limit=10, http_methods=None,
                server_ctx=SimpleNamespace(website_context_pipeline=Pipeline({"llm": {"replies": [""]}})),
            ),
            "example.com",
        )
        return await resources._execute_search(
            ctx, search, resources.AcceptedElicitation(data=resources.SpiderConfirmation(confirm=True))
        )

    result = await request()
    assert result.resources == []
    assert ctx.progress[:3] == [
        (1, None, "Determining target(s)"),
        (2, None, "Found: https://example.com/"),
        (3, None, "Searching for example.com"),
    ]
    if notification_fails:
        assert "Error reporting progress: notification failed" in caplog.text
        assert len(ctx.progress) == 3
    else:
        assert ctx.progress[3] == (4, None, "Querying content")


@pytest.mark.asyncio
async def test_target_detection_async_pipeline_allows_idle_progress(monkeypatch):
    import threading

    from haystack import Pipeline as HaystackPipeline
    from haystack import component

    from shyhurricane.mcp_server import progress

    released = threading.Event()
    received = asyncio.Event()
    updates = []

    @component
    class TargetGenerator:
        @component.output_types(replies=list[str])
        def run(self, query: str):
            assert released.wait(timeout=5), "Progress timer did not run during target detection"
            return {"replies": ['{"target": ["example.com"], "content": ["javascript"]}']}

    pipeline = HaystackPipeline()
    pipeline.add_component("llm", TargetGenerator())

    class TargetPipeline:
        async def run_async(self, data):
            return await pipeline.run_async({"llm": data["builder"]})

    async def send(value, *, message):
        updates.append(message)
        if message.endswith("is still running"):
            released.set()
            received.set()

    ctx = SimpleNamespace(report_progress=send)
    search = resources.SearchPreparation(
        "query", 100, None, SimpleNamespace(website_context_pipeline=TargetPipeline())
    )
    monkeypatch.setattr(progress, "PROGRESS_INTERVAL_SECONDS", 0.01)

    @progress_scope(fresh=True)
    async def request():
        async with progress.idle_progress(ctx, "find_web_resources"):
            await resources._determine_targets(ctx, search, "query")

    try:
        await asyncio.wait_for(request(), timeout=5)
    finally:
        released.set()
    assert received.is_set()
    assert updates[0] == "Determining target(s)"
    assert search.targets == ["example.com"]
    assert search.doc_types == ["javascript"]
