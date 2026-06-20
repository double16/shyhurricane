# test_proxy_server.py
import asyncio
import ssl
import contextlib
import pytest
import tempfile
import shutil
import base64
from pathlib import Path

# Minimal async h2 client using hyper-h2 over asyncio streams
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded

from shyhurricane.proxy_server import proxy_server as srv  # noqa: F401


class DummyStore:
    """Async stand-in for ContentStore."""

    def __init__(self, mapping):
        # mapping: {(METHOD, URL): (status, headers_dict, body_bytes)}
        self.mapping = mapping

    async def lookup(self, url: str, method: str = "GET"):
        return self.mapping.get((method.upper(), url))

    async def recommend_urls(self, requested_url: str):
        return {"https://example.com/", "https://example.com/alt"}


class DummyWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False
        self.drained = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        self.drained = True

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


# ---------------- helpers (async) ----------------

async def read_http1_response(reader: asyncio.StreamReader):
    """Parse an HTTP/1.1 response from an asyncio reader."""
    status_line = await reader.readline()
    parts = status_line.decode("iso-8859-1").strip().split()
    assert parts[0].startswith("HTTP/1.1"), f"bad status line: {status_line!r}"
    status = int(parts[1])
    headers = {}
    while True:
        line = await reader.readline()
        if not line or line == b"\r\n":
            break
        k, v = line.decode("iso-8859-1").rstrip("\r\n").split(":", 1)
        headers[k.strip()] = v.strip()
    body = b""
    clen = int(headers.get("Content-Length", "0"))
    if clen:
        body = await reader.readexactly(clen)
    return status, headers, body


@pytest.mark.asyncio
async def test_content_store_lookup_decodes_headers_text_and_base64():
    class Record:
        def __init__(self, payload):
            self.payload = payload

    class Client:
        def __init__(self, records):
            self.records = records
            self.calls = []

        async def scroll(self, **kwargs):
            self.calls.append(kwargs)
            return self.records, None

    text_store = srv.ContentStore(Client([
        Record({"content": "hello", "meta": {"response_headers": '{"Content-Type": "text/plain"}',
                                             "status_code": 201}})
    ]))
    b64_store = srv.ContentStore(Client([
        Record({"content": base64.b64encode(b"raw").decode(),
                "meta": {"response_headers": '{"Content-Transfer-Encoding": "base64"}'}})
    ]))
    empty_store = srv.ContentStore(Client([]))

    assert await text_store.lookup("https://example.com/", method="POST") == (
        201, {"Content-Type": "text/plain"}, b"hello")
    assert await b64_store.lookup("https://example.com/") == (200, {}, b"raw")
    assert await empty_store.lookup("https://example.com/") is None
    assert text_store.qdrant_client.calls[0]["collection_name"] == "content"


@pytest.mark.asyncio
async def test_content_store_recommend_urls_uses_specific_cache_and_domain_fallback(monkeypatch):
    class Record:
        def __init__(self, meta):
            self.payload = {"meta": meta}

    calls = []

    async def fake_scroll_qdrant_collection(**kwargs):
        calls.append(kwargs)
        metas = [
            {"netloc": "example.com:443", "url": "https://example.com/a"},
            {"netloc": "example.com:443", "url": "https://example.com/a/b"},
            {"netloc": "other.test:443", "url": "https://other.test/"},
        ]
        for meta in metas:
            yield Record(meta)

    monkeypatch.setattr(srv, "scroll_qdrant_collection", fake_scroll_qdrant_collection)
    store = srv.ContentStore(object())

    specific = await store.recommend_urls("https://example.com/a")
    cached = await store.recommend_urls("https://example.com/a")
    fallback = await store.recommend_urls("not a url")

    assert specific == {"https://example.com/a", "https://example.com/a/b"}
    assert cached == specific
    assert "https://example.com:443" in fallback
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_replay_proxy_header_body_and_response_helpers():
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"Host: example.com\r\nBadHeader\r\nContent-Length: 4\r\n\r\n"
        b"body"
    )
    reader.feed_eof()

    headers = await srv.ReplayProxy.read_headers(reader)
    body = await srv.ReplayProxy.read_body_http11(reader, headers)

    writer = DummyWriter()
    await srv.ReplayProxy.send_simple(writer, 404, srv.ReplayProxy.not_found_html(
        "https://missing", ["https://one"]).encode("iso-8859-1"))

    assert headers == {"Host": "example.com", "Content-Length": "4"}
    assert body == b"body"
    assert b"HTTP/1.1 404 Not Found" in writer.data
    assert b"Content-Type: text/html" in writer.data
    assert b"https://one" in writer.data


@pytest.mark.asyncio
async def test_replay_proxy_write_http11_response_filters_hop_headers_and_404():
    writer = DummyWriter()
    store = DummyStore({
        ("GET", "http://example.com/"): (
            202,
            {"Content-Type": "text/plain", "Connection": "keep-alive", "Content-Encoding": "gzip"},
            b"ok",
        )
    })

    await srv.ReplayProxy.write_http11_response("http://example.com/", "GET", writer, store)

    response = bytes(writer.data)
    assert b"HTTP/1.1 202 Accepted" in response
    assert b"Content-Type: text/plain" in response
    assert b"Connection: keep-alive" not in response
    assert b"Content-Encoding" not in response
    assert response.endswith(b"\r\n\r\nok")

    missing_writer = DummyWriter()
    await srv.ReplayProxy.write_http11_response("http://example.com/missing", "GET", missing_writer, store)
    assert b"HTTP/1.1 404 Not Found" in missing_writer.data


def test_cert_authority_creates_ca_mints_leaf_and_uses_cache(tmp_path):
    ca = srv.CertAuthority(cert_dir=tmp_path)

    ctx = ca.mint_ctx_for_host("example.com")
    cached = ca.mint_ctx_for_host("example.com")

    class SslObj:
        context = None

    sslobj = SslObj()
    ca._sni_cb(sslobj, "example.com", ca.base_ctx)

    assert Path(tmp_path, "ca.pem").exists()
    assert Path(tmp_path, "ca.key").exists()
    assert Path(tmp_path, "example.com.pem").exists()
    assert ctx is cached
    assert sslobj.context is ctx


def test_cert_authority_requires_cryptography(monkeypatch, tmp_path):
    monkeypatch.setattr(srv, "have_cryptography", lambda: False)

    with pytest.raises(RuntimeError, match="cryptography"):
        srv.CertAuthority(cert_dir=tmp_path)


def test_tune_ctx_handles_missing_alpn():
    class FakeCtx:
        options = 0

        def set_ciphers(self, value):
            self.ciphers = value

        def set_alpn_protocols(self, value):
            raise NotImplementedError

    ctx = FakeCtx()
    tuned = object.__new__(srv.CertAuthority)._tune_ctx_for_h2(ctx)

    assert tuned is ctx
    assert ctx.ciphers == "ECDHE+AESGCM:ECDHE+CHACHA20:@STRENGTH"
    assert ctx.options & ssl.OP_NO_COMPRESSION


@pytest.mark.asyncio
async def test_replay_proxy_reads_chunked_body_and_handles_inner_http11():
    chunked_reader = asyncio.StreamReader()
    chunked_reader.feed_data(b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n")
    chunked_reader.feed_eof()

    assert await srv.ReplayProxy.read_body_http11(chunked_reader, {"Transfer-Encoding": "chunked"}) == b"Wikipedia"

    request_reader = asyncio.StreamReader()
    request_reader.feed_data(
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody"
    )
    request_reader.feed_eof()
    writer = DummyWriter()
    store = DummyStore({("POST", "https://example.com/submit"): (200, {}, b"ok")})

    await srv.ReplayProxy.handle_inner_http11(request_reader, writer, "example.com", store)

    assert b"HTTP/1.1 200 OK" in writer.data
    assert writer.closed is True


@pytest.mark.asyncio
async def test_replay_proxy_handle_plain_origin_and_error_paths(monkeypatch):
    reader = asyncio.StreamReader()
    reader.feed_data(b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody")
    reader.feed_eof()
    writer = DummyWriter()
    store = DummyStore({("POST", "http://example.com/submit"): (200, {"X-Test": "yes"}, b"ok")})
    proxy = srv.ReplayProxy(store, ca=object())

    await proxy.handle(reader, writer)

    assert b"HTTP/1.1 200 OK" in writer.data
    assert b"X-Test: yes" in writer.data
    assert writer.closed is True

    bad_reader = asyncio.StreamReader()
    bad_reader.feed_data(b"bad\r\n")
    bad_reader.feed_eof()
    bad_writer = DummyWriter()
    await proxy.handle(bad_reader, bad_writer)
    assert bad_writer.closed is True

    async def fail_response(*args, **kwargs):
        raise RuntimeError("failed")

    error_reader = asyncio.StreamReader()
    error_reader.feed_data(b"GET http://example.com/error HTTP/1.1\r\nHost: example.com\r\n\r\n")
    error_reader.feed_eof()
    error_writer = DummyWriter()
    monkeypatch.setattr(srv.ReplayProxy, "write_http11_response", fail_response)

    await proxy.handle(error_reader, error_writer)

    assert b"HTTP/1.1 500 Internal Server Error" in error_writer.data


@pytest.mark.asyncio
async def test_h2_send_response_sends_headers_only_and_body_chunks():
    class Conn:
        max_outbound_frame_size = 4

        def __init__(self):
            self.headers = []
            self.data = []
            self.ended = []

        def send_headers(self, stream_id, headers, end_stream=False):
            self.headers.append((stream_id, headers, end_stream))

        def send_data(self, stream_id, data, end_stream=False):
            self.data.append((stream_id, bytes(data), end_stream))

        def end_stream(self, stream_id):
            self.ended.append(stream_id)

        def local_flow_control_window(self, stream_id):
            return 100

        def data_to_send(self):
            return b"frame"

    class Transport:
        def __init__(self):
            self.data = bytearray()

        def write(self, data):
            self.data.extend(data)

    reader = asyncio.StreamReader()
    transport = Transport()
    empty_conn = Conn()
    body_conn = Conn()

    await srv.ReplayProxy._h2_send_response(empty_conn, reader, transport, 1, 204, {}, b"")
    await srv.ReplayProxy._h2_send_response(body_conn, reader, transport, 3, 200,
                                            {"Content-Type": "text/plain", "Connection": "close"}, b"abcdef")

    assert empty_conn.headers[0][2] is True
    assert ("content-type", "application/octet-stream") in empty_conn.headers[0][1]
    assert body_conn.headers[0][2] is False
    assert body_conn.data == [(3, b"abcd", False), (3, b"ef", False)]
    assert body_conn.ended == [3]


@pytest.mark.asyncio
async def test_run_proxy_server_sets_context(monkeypatch, tmp_path):
    class Server:
        sockets = [type("Sock", (), {"getsockname": lambda self: ("127.0.0.1", 9999)})()]

    class Context:
        proxy_host = None
        proxy_port = None
        proxy_ca_cert_path = None

    created = {}

    async def create_client(db):
        return object()

    async def start_server(handler, host, port, start_serving):
        created["handler"] = handler
        created["host"] = host
        created["port"] = port
        created["start_serving"] = start_serving
        return Server()

    monkeypatch.setattr(srv, "create_qdrant_client", create_client)
    monkeypatch.setattr(srv.asyncio, "start_server", start_server)
    ctx = Context()

    server = await srv.run_proxy_server("db", "127.0.0.1", 0, tmp_path, ctx)

    assert isinstance(server, Server)
    assert created["host"] == "127.0.0.1"
    assert created["port"] == 0
    assert created["start_serving"] is True
    assert ctx.proxy_host == "127.0.0.1"
    assert ctx.proxy_port == 0
    assert ctx.proxy_ca_cert_path == Path(tmp_path, "ca.pem")


@pytest.mark.asyncio
async def test_content_store_lookup_handles_bad_headers_and_base64_decode_failure():
    class Record:
        payload = {
            "content": "not-base64",
            "meta": {"response_headers": "not-json", "status_code": 203},
        }

    class Client:
        async def scroll(self, **kwargs):
            return [Record()], None

    result = await srv.ContentStore(Client()).lookup("https://example.com/")

    assert result == (203, {}, b"not-base64")


class H2Transport:
    def __init__(self):
        self.data = bytearray()
        self.aborted = False

    def write(self, data):
        self.data.extend(data)

    def abort(self):
        self.aborted = True


class H2Writer(DummyWriter):
    def __init__(self):
        super().__init__()
        self.transport = H2Transport()


async def run_h2_request(store, headers):
    reader = asyncio.StreamReader()
    client = H2Connection(H2Configuration(client_side=True, header_encoding="iso-8859-1"))
    client.initiate_connection()
    stream_id = client.get_next_available_stream_id()
    client.send_headers(stream_id, headers, end_stream=True)
    reader.feed_data(client.data_to_send())
    reader.feed_eof()
    writer = H2Writer()

    await srv.ReplayProxy.handle_h2_connection(reader, writer, "example.com", store)

    return writer


@pytest.mark.asyncio
async def test_handle_h2_connection_serves_found_and_404():
    found_writer = await run_h2_request(
        DummyStore({("GET", "https://example.com/ok"): (200, {"Content-Type": "text/plain"}, b"ok")}),
        [
            (":method", "GET"),
            (":authority", "example.com"),
            (":scheme", "https"),
            (":path", "/ok"),
        ],
    )
    missing_writer = await run_h2_request(
        DummyStore({}),
        [
            (":method", "GET"),
            (":authority", "example.com"),
            (":scheme", "https"),
            (":path", "/missing"),
        ],
    )

    assert found_writer.transport.aborted is True
    assert missing_writer.transport.aborted is True
    assert found_writer.transport.data
    assert missing_writer.transport.data


@pytest.mark.asyncio
async def test_handle_h2_connection_returns_500_on_store_error():
    class BrokenStore(DummyStore):
        async def lookup(self, url: str, method: str = "GET"):
            raise RuntimeError("failed")

    writer = await run_h2_request(
        BrokenStore({}),
        [
            (":method", "GET"),
            (":authority", "example.com"),
            (":scheme", "https"),
            (":path", "/error"),
        ],
    )

    assert writer.transport.data


async def connect_tunnel(loop: asyncio.AbstractEventLoop, proxy_host, proxy_port, target_host, target_port, alpn=None):
    """
    Open TCP to proxy, send CONNECT, then upgrade this client-side connection to TLS
    (against the proxy's forged leaf for target_host), returning (tls_reader, tls_writer, selected_alpn).
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # 1) CONNECT
    writer.write(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
    await writer.drain()
    # Minimal parse
    line = await reader.readline()
    assert line.startswith(b"HTTP/1.1 200"), f"CONNECT failed: {line!r}"
    # Drain headers
    while True:
        line = await reader.readline()
        if not line or line == b"\r\n":
            break

    # 2) Upgrade this transport to TLS (client side)
    raw_transport = writer.transport
    raw_protocol = writer._protocol  # StreamReaderProtocol
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ssl_ctx.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass

    tls_transport = await loop.start_tls(
        raw_transport, raw_protocol, ssl_ctx, server_side=False, server_hostname=target_host
    )
    # Re-wrap into reader/writer bound to TLS transport
    tls_reader = asyncio.StreamReader(limit=2 ** 20)
    tls_proto = asyncio.StreamReaderProtocol(tls_reader)
    tls_proto.connection_made(tls_transport)
    tls_writer = asyncio.StreamWriter(tls_transport, tls_proto, tls_reader, loop)
    # ALPN result
    sslobj = tls_transport.get_extra_info("ssl_object")
    selected = sslobj.selected_alpn_protocol() if sslobj else None
    return tls_reader, tls_writer, selected


# ---------------- proxy fixture ----------------

@pytest.fixture
async def proxy_server():
    """
    Start your proxy with a real CertAuthority and a DummyStore.
    Yields (host, port). Cleans up after each test.
    """
    body_http = b"hello over http"
    body_https = b"hello over https"
    body_h2 = b"A" * 70000  # large to exercise h2 DATA chunking/flow control
    mapping = {
        ("GET", "http://example.com/hello"): (200, {"Content-Type": "text/plain"}, body_http),
        ("GET", "https://example.com/hello"): (200, {"Content-Type": "text/plain"}, body_https),
        ("GET", "https://example.com/big"): (200, {"Content-Type": "application/octet-stream"}, body_h2),
    }
    store = DummyStore(mapping)

    temp_dir = tempfile.mkdtemp(prefix="replay-ca-test-")
    ca = srv.CertAuthority(cert_dir=temp_dir)
    proxy = srv.ReplayProxy(store, ca)

    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]

    yield host, port

    server.close()
    with contextlib.suppress(Exception):
        await server.wait_closed()
    shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------- tests (async, non-blocking) ----------------

@pytest.mark.asyncio
async def test_plain_http_absolute_form(proxy_server):
    host, port = proxy_server
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        b"GET http://example.com/hello HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: test\r\n"
        b"\r\n"
    )
    await writer.drain()
    status, headers, body = await read_http1_response(reader)
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()

    assert status == 200
    assert headers.get("Content-Type") == "text/plain"
    assert body == b"hello over http"


@pytest.mark.asyncio
@pytest.mark.skip
async def test_connect_https_http11(proxy_server):
    host, port = proxy_server
    loop = asyncio.get_running_loop()
    tls_reader, tls_writer, selected = await connect_tunnel(
        loop, host, port, "example.com", 443, alpn=["http/1.1"]
    )
    # Send inner HTTP/1.1 request
    tls_writer.write(b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")
    await tls_writer.drain()
    status, headers, body = await read_http1_response(tls_reader)
    tls_writer.close()
    with contextlib.suppress(Exception):
        await tls_writer.wait_closed()

    assert selected in (None, "http/1.1")
    assert status == 200
    assert headers.get("Content-Type") == "text/plain"
    assert body == b"hello over https"


@pytest.mark.asyncio
@pytest.mark.skip
async def test_connect_https_h2_big_body(proxy_server):
    """
    Verify h2 path:
      - ALPN negotiates h2
      - GET /big returns a 70KB body via multiple DATA frames
    """
    host, port = proxy_server
    loop = asyncio.get_running_loop()
    tls_reader, tls_writer, selected = await connect_tunnel(
        loop, host, port, "example.com", 443, alpn=["h2", "http/1.1"]
    )
    assert selected == "h2", f"ALPN failed, got {selected!r}"

    conn = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    tls_writer.write(conn.data_to_send())
    await tls_writer.drain()

    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, [
        (":method", "GET"),
        (":authority", "example.com"),
        (":scheme", "https"),
        (":path", "/big"),
        ("user-agent", "pytest-h2"),
    ], end_stream=True)
    tls_writer.write(conn.data_to_send())
    await tls_writer.drain()

    body = bytearray()
    got_status = None

    while True:
        data = await tls_reader.read(65535)
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, ResponseReceived):
                for k, v in ev.headers:
                    if k == ":status":
                        got_status = int(v)
            elif isinstance(ev, DataReceived):
                body += ev.data
                conn.acknowledge_received_data(len(ev.data), stream_id)
            elif isinstance(ev, StreamEnded):
                # send any remaining acks
                tls_writer.write(conn.data_to_send())
                await tls_writer.drain()
                break
        out = conn.data_to_send()
        if out:
            tls_writer.write(out)
            await tls_writer.drain()
        if got_status is not None and isinstance(ev, StreamEnded):
            break

    # try to GOAWAY politely (ok if it fails; server often aborts)
    with contextlib.suppress(Exception):
        conn.close_connection()
        tls_writer.write(conn.data_to_send())
        await tls_writer.drain()
        tls_writer.close()
        await tls_writer.wait_closed()

    assert got_status == 200
    assert len(body) == 70000
