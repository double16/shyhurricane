import pytest
from haystack import Document

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
