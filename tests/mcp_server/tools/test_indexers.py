import json

import httpx
import pytest

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

    monkeypatch.setattr(indexers, "deobfuscate_javascript", deobfuscate)

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
async def test_index_http_url_omits_large_or_binary_body(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(indexers, "log_tool_history", noop)
    monkeypatch.setattr(indexers, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(indexers, "get_additional_hosts", lambda ctx, additional=None: {})
    monkeypatch.setattr(indexers.httpx, "AsyncClient", lambda: FakeAsyncClient())

    result = await indexers.index_http_url(None, "https://example.com/app.js", content_length_limit=1)

    assert result.contents is None
    assert json.loads(ctx.ingest_queue.items[0])["response"]["body"] is None


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
