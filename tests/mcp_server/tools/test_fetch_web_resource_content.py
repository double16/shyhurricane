import pytest
from haystack import Document

import shyhurricane.mcp_server.tools.fetch_web_resource_content as fetch


def make_doc(doc_id="doc-1", content="abcdef", url="https://example.com/app.js"):
    return Document(
        id=doc_id,
        content=content,
        meta={
            "url": url,
            "host": "example.com",
            "domain": "example.com",
            "port": 443,
            "http_method": "GET",
            "status_code": 200,
            "content_type": "application/javascript",
            "response_headers": '{"content-type": "application/javascript"}',
        },
    )


class AsyncStore:
    def __init__(self, docs):
        self.docs = docs
        self.async_filters = []
        self.sync_filters = []

    async def filter_documents_async(self, filters):
        self.async_filters.append(filters)
        return self.docs

    def filter_documents(self, filters):
        self.sync_filters.append(filters)
        return self.docs


class ServerContext:
    def __init__(self, stores):
        self.stores = stores


async def noop(*args, **kwargs):
    return None


def patch_server_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(fetch, "get_server_context", get_fake_server_context)


@pytest.mark.asyncio
async def test_find_document_by_type_and_id_returns_none_for_missing_store(monkeypatch):
    patch_server_context(monkeypatch, ServerContext({}))

    assert await fetch._find_document_by_type_and_id("content", "missing") is None


@pytest.mark.asyncio
async def test_find_document_by_type_and_id_uses_async_store(monkeypatch):
    doc = make_doc()
    store = AsyncStore([doc])
    patch_server_context(monkeypatch, ServerContext({"content": store}))

    assert await fetch._find_document_by_type_and_id("content", "doc-1") is doc
    assert store.async_filters == [{"field": "id", "operator": "==", "value": "doc-1"}]


@pytest.mark.asyncio
async def test_fetch_web_resource_content_by_web_url_returns_partial_contents(monkeypatch):
    doc = make_doc(content="0123456789")
    patch_server_context(monkeypatch, ServerContext({"content": AsyncStore([doc])}))
    monkeypatch.setattr(fetch, "log_tool_history", noop)

    result = await fetch.fetch_web_resource_content(None, "web://content/doc-1", 2, 4)

    assert result.url == "https://example.com/app.js"
    assert result.contents.text == "2345"
    assert result.contents.offset == 2
    assert result.contents.total_length == 10
    assert result.contents.has_more is True
    assert result.response_headers == {"content-type": "application/javascript"}


@pytest.mark.asyncio
async def test_fetch_web_resource_content_by_http_url_and_offset_past_end(monkeypatch):
    doc = make_doc(content="short")
    store = AsyncStore([doc])
    patch_server_context(monkeypatch, ServerContext({"content": store}))
    monkeypatch.setattr(fetch, "log_tool_history", noop)

    result = await fetch.fetch_web_resource_content(None, "https://example.com/app.js", 99, 10)

    assert result.contents.text == ""
    assert result.contents.has_more is False
    assert store.sync_filters[0]["conditions"][1]["value"] == "https://example.com/app.js"


@pytest.mark.asyncio
async def test_fetch_web_resource_content_returns_none_without_content(monkeypatch):
    doc = make_doc(content=None)
    patch_server_context(monkeypatch, ServerContext({"content": AsyncStore([doc])}))
    monkeypatch.setattr(fetch, "log_tool_history", noop)

    assert await fetch.fetch_web_resource_content(None, "web://content/doc-1") is None


@pytest.mark.asyncio
async def test_web_resource_returns_full_text_resource(monkeypatch):
    doc = make_doc(content="full")
    patch_server_context(monkeypatch, ServerContext({"content": AsyncStore([doc])}))

    result = await fetch.web_resource("content", "doc-1")

    assert str(result.uri) == "web://content/doc-1"
    assert result.mimeType == "application/javascript"
    assert result.text == "full"
