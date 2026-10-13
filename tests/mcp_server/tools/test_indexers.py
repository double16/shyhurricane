import asyncio
import json
import sqlite3
import subprocess

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

import shyhurricane.mcp_server.tools.indexers as indexers


async def noop(*args, **kwargs):
    return None


class Queue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class ServerContext:
    open_world = True

    def __init__(self):
        self.ingest_queue = Queue()

    async def enqueue_ingest(self, item):
        self.ingest_queue.put(item)


class FakeRequest:
    def __init__(self, chunks):
        self.chunks = chunks

    async def stream(self):
        for chunk in self.chunks:
            yield chunk


def patch_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(indexers, "get_server_context", get_fake_server_context)


@pytest.mark.asyncio
async def test_index_request_body_rejects_empty_body(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    response = await indexers.index_request_body(FakeRequest([]))

    assert response.status_code == 400
    assert ctx.ingest_queue.items == []


@pytest.mark.asyncio
async def test_index_request_body_indexes_katana_jsonl(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    first = json.dumps({"request": {"endpoint": "https://example.com"}, "response": {}, "timestamp": "now"}) + "\n"
    second = json.dumps({"request": {"endpoint": "https://example.com/a"}, "response": {}, "timestamp": "now"}) + "\n"

    response = await indexers.index_request_body(FakeRequest([first.encode(), second.encode()]))

    assert response.status_code == 201
    assert ctx.ingest_queue.items == [first.strip(), second.strip()]


@pytest.mark.asyncio
async def test_index_request_body_indexes_csv_and_raw_body(monkeypatch):
    csv_ctx = ServerContext()
    raw_ctx = ServerContext()
    monkeypatch.setattr(indexers, "is_katana_jsonl", lambda line: False)
    monkeypatch.setattr(indexers, "is_http_csv", lambda first, second: True)

    class Row:
        def __init__(self, value):
            self.value = value

        def to_katana(self):
            return self.value

    monkeypatch.setattr(indexers, "http_csv_generator", lambda lines: [Row("katana-1"), Row("katana-2")])
    patch_context(monkeypatch, csv_ctx)

    csv_response = await indexers.index_request_body(FakeRequest([b"header\n", b"row\n"]))

    monkeypatch.setattr(indexers, "is_http_csv", lambda first, second: False)
    patch_context(monkeypatch, raw_ctx)
    raw_response = await indexers.index_request_body(FakeRequest([b"one\n", b"two\n"]))

    assert csv_response.status_code == 201
    assert csv_ctx.ingest_queue.items == ["katana-1", "katana-2"]
    assert raw_response.status_code == 201
    assert raw_ctx.ingest_queue.items == ["one\ntwo"]


@pytest.mark.asyncio
@pytest.mark.parametrize("body, expected", [
    (b'{"request": {"endpoint": "https://example.com"}, "response": {}, "timestamp": "now"}\n', "katana"),
    (b"single raw body\n", "raw"),
])
async def test_index_request_body_accepts_single_line(monkeypatch, body, expected):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    response = await indexers.index_request_body(FakeRequest([body]))

    assert response.status_code == 201
    assert len(ctx.ingest_queue.items) == 1
    assert (ctx.ingest_queue.items[0].startswith("{")) is (expected == "katana")


class FakeResponse:
    status_code = 200
    text = "console.log('x')"
    headers = {
        "Content-Type": "application/javascript",
        "Content-Length": "16",
        "X-Test": "yes",
    }


class FakeAsyncClient:
    def __init__(self):
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def request(self, **kwargs):
        self.requests.append(kwargs)
        return FakeResponse()


@pytest.mark.asyncio
async def test_index_http_url_fetches_indexes_and_deobfuscates(monkeypatch):
    ctx = ServerContext()
    client = FakeAsyncClient()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {"example.com": "127.0.0.1"})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", lambda: client)

    async def deobfuscate(ctx, body):
        return "console.log('readable')"

    monkeypatch.setattr(indexers, "deobfuscate_javascript_full", deobfuscate)

    result = await indexers.index_http_url(
        None,
        "https://example.com/app.js",
        method="POST",
        user_agent="agent",
        request_headers="X-Extra: 1",
        cookies="sid=abc",
        params="debug=1",
        request_body="body",
        content_length_limit=100,
    )

    assert result.url == "https://example.com/app.js"
    assert result.contents.text == "console.log('readable')"
    assert result.response_headers["X-Test"] == "yes"
    assert client.requests[0]["url"] == "https://127.0.0.1/app.js"
    assert client.requests[0]["headers"]["Host"] == "example.com"
    queued = json.loads(ctx.ingest_queue.items[0])
    assert queued["request"]["endpoint"] == "https://example.com/app.js"
    assert queued["response"]["body"] == "console.log('x')"


@pytest.mark.asyncio
async def test_index_http_url_previews_large_body_without_losing_indexed_content(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", lambda: FakeAsyncClient())

    async def transform(ctx, body):
        return body

    monkeypatch.setattr(indexers, "deobfuscate_javascript_full", transform)
    result = await indexers.index_http_url(None, "https://example.com/app.js", content_length_limit=1)

    assert result.contents.text == "c"
    assert result.pagination.next_page_token is not None
    assert result.pagination.total_items == len(FakeResponse.text)
    assert json.loads(ctx.ingest_queue.items[0])["response"]["body"] == FakeResponse.text


@pytest.mark.asyncio
async def test_index_http_url_returns_none_for_request_exception(monkeypatch):
    class FailingClient(FakeAsyncClient):
        async def request(self, **kwargs):
            raise httpx.RequestError("failed")

    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", lambda: FailingClient())

    assert await indexers.index_http_url(None, "https://example.com/") is None


@pytest.mark.asyncio
async def test_ingest_waits_for_durable_write_without_blocking_http_loop(tmp_path, monkeypatch):
    import asyncio
    from threading import Event

    from shyhurricane.persistent_queue import AsyncIngestWriter, open_persistent_queue, read_active_queue_size

    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = Event()
    queue = open_persistent_queue(str(tmp_path))
    queue.close()
    writer = AsyncIngestWriter(str(tmp_path))
    original_put = writer._put

    def slow_put(item):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5)
        return original_put(item)

    monkeypatch.setattr(writer, "_put", slow_put)
    ctx = ServerContext()
    ctx.enqueue_ingest = writer.put
    patch_context(monkeypatch, ctx)
    task = asyncio.create_task(indexers.index_request_body(FakeRequest([b"raw body"])))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert not task.done()
        assert read_active_queue_size(tmp_path) == 0
        release.set()
        assert (await task).status_code == 201
        assert read_active_queue_size(tmp_path) == 1
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.to_thread(writer.close)


@pytest.mark.asyncio
async def test_ingest_propagates_partial_write_failure(monkeypatch):
    ctx = ServerContext()

    async def enqueue(item):
        if ctx.ingest_queue.items:
            raise OSError("disk full")
        ctx.ingest_queue.put(item)

    ctx.enqueue_ingest = enqueue
    patch_context(monkeypatch, ctx)
    first = json.dumps({"request": {"endpoint": "https://example.com"}, "response": {}, "timestamp": "now"})
    with pytest.raises(OSError, match="disk full"):
        await indexers.index_request_body(FakeRequest([f"{first}\n{first}".encode()]))
    assert ctx.ingest_queue.items == [first]


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [None, "wrong", "1", "999999"])
async def test_index_body_pagination_ignores_content_length(monkeypatch, length, result_store):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    text = "π🙂<html>body</html>"

    class Response:
        status_code = 200
        headers = {"Content-Type": "text/html", **({"Content-Length": length} if length is not None else {})}

        def __init__(self):
            self.text = text

    class Client(FakeAsyncClient):
        async def request(self, **kwargs):
            return Response()

    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", Client)
    first = await indexers.index_http_url(None, "https://example.com/", content_length_limit=4)
    assert first.contents.text == text[:4]
    assert first.contents.offset == 0
    assert first.contents.total_length == len(text)
    assert json.loads(ctx.ingest_queue.items[0])["response"]["body"] == text
    reconstructed = first.contents.text
    current = first
    while current.pagination.next_page_token:
        current = (await get_result_page(None, current.pagination.next_page_token)).result
        assert current.contents.offset == len(reconstructed)
        reconstructed += current.contents.text
    assert reconstructed == text
    assert current.pagination.next_page_token is None
    assert len(ctx.ingest_queue.items) == 1


@pytest.mark.asyncio
async def test_index_binary_body_returns_only_metadata(monkeypatch):
    class BinaryClient(FakeAsyncClient):
        async def request(self, **kwargs):
            response = FakeResponse()
            response.headers = {"Content-Type": "image/png"}
            return response

    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", BinaryClient)
    result = await indexers.index_http_url(None, "https://example.com/image.png")
    assert result.contents is None
    assert result.pagination is None
    assert json.loads(ctx.ingest_queue.items[0])["response"]["body"] is None


@pytest.mark.asyncio
async def test_index_preview_limit_applies_after_javascript_expansion(monkeypatch):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", FakeAsyncClient)

    async def expand(ctx, body):
        return "expanded" * 100

    monkeypatch.setattr(indexers, "deobfuscate_javascript_full", expand)
    first = await indexers.index_http_url(None, "https://example.com/a.js", content_length_limit=8)
    assert first.contents.text == "expanded"
    assert first.pagination.total_items == 800
    assert (await get_result_page(None, first.pagination.next_page_token)).result.contents.text == "expanded"
    assert json.loads(ctx.ingest_queue.items[0])["response"]["body"] == FakeResponse.text


@pytest.fixture
def http_tool_context(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: additional or {})
    return ctx


def mock_http_response(monkeypatch, response):
    class Client(FakeAsyncClient):
        async def request(self, **kwargs):
            return response

    monkeypatch.setattr(indexers.httpx, "AsyncClient", Client)


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{}, {"Content-Type": ""}])
@pytest.mark.parametrize("text", ["", "response body"])
async def test_missing_content_type(monkeypatch, http_tool_context, headers, text, result_store):
    from shyhurricane.mcp_server.tools.get_result_page import get_result_page

    response = httpx.Response(302, headers=headers, content=text.encode("utf-8"))
    mock_http_response(monkeypatch, response)
    result = await indexers.index_http_url(None, "https://example.com/", content_length_limit=4)
    queued = json.loads(http_tool_context.ingest_queue.items[0])
    assert queued["response"]["body"] == text
    assert queued["response"]["headers"] == dict(response.headers)
    assert result.response_headers == dict(response.headers)
    assert result.status_code == 302
    if text:
        assert result.contents.mime_type == ""
        reconstructed = result.contents.text
        while result.pagination.next_page_token:
            result = (await get_result_page(None, result.pagination.next_page_token)).result
            reconstructed += result.contents.text
        assert reconstructed == text
        assert len(http_tool_context.ingest_queue.items) == 1
    else:
        assert result.contents is None
        assert result.pagination is None


@pytest.mark.asyncio
async def test_binary_response_never_decodes_text(monkeypatch, http_tool_context):
    class BinaryResponse:
        status_code = 200
        headers = {"Content-Type": "application/pdf"}

        @property
        def text(self):
            raise AssertionError("Binary response must not be decoded")

    mock_http_response(monkeypatch, BinaryResponse())
    result = await indexers.index_http_url(None, "https://example.com/file.pdf")
    assert result.contents is None
    assert result.pagination is None
    assert json.loads(http_tool_context.ingest_queue.items[0])["response"]["body"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["not a URL", "https://example.com:99999/", "https://example.com:wrong/",
                                      "ftp://example.com/file"])
async def test_invalid_url_rejected_before_fetch(monkeypatch, http_tool_context, url):
    def unexpected_client():
        pytest.fail("Invalid input must not issue a request")

    monkeypatch.setattr(indexers.httpx, "AsyncClient", unexpected_client)
    with pytest.raises(ToolError, match="valid HTTP or HTTPS URL"):
        await indexers.index_http_url(None, url)
    assert http_tool_context.ingest_queue.items == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["additional_hosts", "cookies", "request_headers", "params"])
@pytest.mark.parametrize("value", [{"name": None}, '{"name": 42}', {1: "value"}])
async def test_invalid_request_mapping_rejected(monkeypatch, http_tool_context, name, value):
    def unexpected_client():
        pytest.fail("Invalid input must not issue a request")

    monkeypatch.setattr(indexers.httpx, "AsyncClient", unexpected_client)
    with pytest.raises(ToolError, match=f"{name} must contain string"):
        await indexers.index_http_url(None, "https://example.com/", **{name: value})
    assert http_tool_context.ingest_queue.items == []


def test_request_mapping_accepts_json_and_delimited_strings():
    assert indexers._request_mapping('{"X-Test": "yes"}', "request_headers") == {"X-Test": "yes"}
    assert indexers._request_mapping("a=b;c=d", "cookies", "=", ";") == {"a": "b", "c": "d"}
    assert indexers._request_mapping(None, "params") == {}


@pytest.mark.asyncio
async def test_disabled_network_rejected(monkeypatch, http_tool_context):
    http_tool_context.open_world = False

    def unexpected_client():
        pytest.fail("Disabled network must not issue a request")

    monkeypatch.setattr(indexers.httpx, "AsyncClient", unexpected_client)
    with pytest.raises(ToolError, match="Network access has been disabled"):
        await indexers.index_http_url(None, "https://example.com/")
    assert http_tool_context.ingest_queue.items == []


@pytest.mark.asyncio
@pytest.mark.parametrize("error, message", [
    (httpx.InvalidURL("bad URL"), "rejected the request URL"),
    (TypeError("bad header value"), "Invalid HTTP request inputs"),
    (ValueError("bad input"), "Invalid HTTP request inputs"),
    (UnicodeEncodeError("ascii", "é", 0, 1, "not ASCII"), "Invalid HTTP request inputs"),
])
async def test_http_client_input_errors(monkeypatch, http_tool_context, error, message):
    class Client(FakeAsyncClient):
        async def request(self, **kwargs):
            raise error

    monkeypatch.setattr(indexers.httpx, "AsyncClient", Client)
    with pytest.raises(ToolError, match=message):
        await indexers.index_http_url(None, "https://example.com/")
    assert http_tool_context.ingest_queue.items == []


@pytest.mark.asyncio
async def test_real_httpx_rejects_non_ascii_header(http_tool_context):
    with pytest.raises(ToolError, match="Invalid HTTP request inputs"):
        await indexers.index_http_url(None, "https://example.com/", request_headers={"X-Test": "é"})
    assert http_tool_context.ingest_queue.items == []


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout, httpx.TooManyRedirects,
                                          httpx.RemoteProtocolError])
async def test_network_failures_return_none(monkeypatch, http_tool_context, error_type):
    class Client(FakeAsyncClient):
        async def request(self, **kwargs):
            raise error_type("request failed")

    monkeypatch.setattr(indexers.httpx, "AsyncClient", Client)
    assert await indexers.index_http_url(None, "https://example.com/", follow_redirects=True) is None
    assert http_tool_context.ingest_queue.items == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 500])
async def test_http_error_status_still_indexes(monkeypatch, http_tool_context, status):
    mock_http_response(monkeypatch, httpx.Response(status, headers={"Content-Type": "text/plain"}, text="error"))
    result = await indexers.index_http_url(None, "https://example.com/")
    assert result.status_code == status
    assert result.contents.text == "error"
    assert json.loads(http_tool_context.ingest_queue.items[0])["response"]["status_code"] == status


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [OSError("disk full"), sqlite3.OperationalError("locked"),
                                    RuntimeError("Ingest writer is closed")])
async def test_ingestion_failure_reports_stage(monkeypatch, http_tool_context, error):
    from unittest.mock import AsyncMock

    mock_http_response(monkeypatch, FakeResponse())
    enqueue = AsyncMock(side_effect=error)
    http_tool_context.enqueue_ingest = enqueue
    with pytest.raises(ToolError, match="Response fetched, but queueing for ingestion failed"):
        await indexers.index_http_url(None, "https://example.com/")
    enqueue.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [FileNotFoundError("docker missing"), OSError("temp file failed"),
                                    subprocess.SubprocessError("command failed")])
async def test_javascript_infrastructure_failure_preserves_response(monkeypatch, http_tool_context, error):
    mock_http_response(monkeypatch, FakeResponse())

    async def fail_transform(ctx, body):
        raise error

    monkeypatch.setattr(indexers, "deobfuscate_javascript_full", fail_transform)
    result = await indexers.index_http_url(None, "https://example.com/app.js")
    assert result.contents.text == FakeResponse.text
    assert len(http_tool_context.ingest_queue.items) == 1
    assert json.loads(http_tool_context.ingest_queue.items[0])["response"]["body"] == FakeResponse.text


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["request", "enqueue", "transform"])
async def test_cancellation_propagates(monkeypatch, http_tool_context, stage):
    from unittest.mock import AsyncMock

    mock_http_response(monkeypatch, FakeResponse())
    cancelled = AsyncMock(side_effect=asyncio.CancelledError)
    if stage == "request":
        class Client(FakeAsyncClient):
            request = cancelled

        monkeypatch.setattr(indexers.httpx, "AsyncClient", Client)
    elif stage == "enqueue":
        http_tool_context.enqueue_ingest = cancelled
    else:
        monkeypatch.setattr(indexers, "deobfuscate_javascript_full", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await indexers.index_http_url(None, "https://example.com/app.js")
    assert len(http_tool_context.ingest_queue.items) == (1 if stage == "transform" else 0)


@pytest.mark.asyncio
async def test_preview_storage_error_reports_already_queued(monkeypatch, http_tool_context, result_store):
    def fail_save(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(result_store, "save", fail_save)
    mock_http_response(monkeypatch, httpx.Response(200, text="body"))
    with pytest.raises(ToolError, match="Response queued for ingestion.*may enqueue the response again"):
        await indexers.index_http_url(None, "https://example.com/")
    assert len(http_tool_context.ingest_queue.items) == 1
