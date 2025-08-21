# test_proxy_server.py
import asyncio
import ssl
import contextlib
import pytest

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
        l = await reader.readline()
        if not l or l == b"\r\n":
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

    import tempfile, shutil
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

    # Minimal async h2 client using hyper-h2 over asyncio streams
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded

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
