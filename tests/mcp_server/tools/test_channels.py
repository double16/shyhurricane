import asyncio
import base64
import sys
import time
import pytest

from shyhurricane.mcp_server import ServerContext

MODULE_UNDER_TEST = "shyhurricane.mcp_server.tools.channels"

mod = __import__(MODULE_UNDER_TEST, fromlist=["*"])


# Minimal Fake Context that matches _mgr(ctx) expectations

class _FakeLifespan:
    def __init__(self):
        self.channel_manager = mod.ChannelManager()
        self.work_path = "/var/tmp"
        self.cached_get_additional_hosts = {}


class _FakeRequestContext:
    def __init__(self):
        self.lifespan_context = _FakeLifespan()


class FakeContext:
    """Matches ctx.request_context.lifespan_context.channel_manager used by _mgr()."""

    def __init__(self):
        self.request_context = _FakeRequestContext()


# Common helpers

def b64_to_bytes(ev):
    return base64.b64decode(ev.data_b64) if getattr(ev, "data_b64", None) else b""


async def poll_until(ctx, channel_id, pred, timeout=3.0):
    """Poll repeatedly until pred(events) is True or timeout; returns accumulated events."""
    start = time.time()
    collected = []
    while time.time() - start < timeout:
        res = await mod.channel_poll(
            ctx,
            channel_id=channel_id,
            timeout=0.25,
            max_events=1024,
            min_events=1,
        )
        collected.extend(res.events)
        if pred(collected):
            return collected
    return collected


# Fixtures

@pytest.fixture
def ctx():
    return FakeContext()


@pytest.fixture(autouse=True)
def noop_log_tool_history(monkeypatch):
    async def _noop(ctx, name, **kwargs):  # matches log_tool_history(ctx, "...") signature
        return None

    monkeypatch.setattr(mod, "log_tool_history", _noop, raising=False)


@pytest.fixture(autouse=True)
def noop_get_server_context(monkeypatch):
    async def _noop():  # matches get_server_context(ctx, "...") signature
        return ServerContext(
            db="",
            cache_path="/var/tmp",
            document_pipeline=None,
            website_context_pipeline=None,
            ingest_queue=None,
            ingest_pool=None,
            task_queue=None,
            task_pool=None,
            spider_result_queue=None,
            port_scan_result_queue=None,
            dir_busting_result_queue=None,
            stores={},
            chroma_client=None,
            mcp_session_volume="mcp_session",
            seclists_volume="seclists",
            disable_elicitation=True,
            open_world=True,
        )

    monkeypatch.setattr(mod, "get_server_context", _noop, raising=False)


# Forward channel tests (Docker-free by mocking create_subprocess_exec)

ECHO_CODE = (
    "import sys\n"
    "print('ready', flush=True)\n"
    "for line in sys.stdin:\n"
    "    sys.stdout.write(line)\n"
    "    sys.stdout.flush()\n"
)


@pytest.fixture
def mock_subprocess(monkeypatch):
    orig = asyncio.create_subprocess_exec

    async def fake_create_subprocess_exec(*args, **kwargs):
        # Ignore the 'docker ... image ... cmd...' invocation and run a simple echo script instead
        return await orig(
            sys.executable, "-u", "-c", ECHO_CODE,
            stdin=kwargs.get("stdin"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            limit=kwargs.get("limit", 2 ** 16),
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    yield
    # restore implicitly when fixture exits


@pytest.mark.asyncio
async def test_forward_create_status_send_poll_close(ctx, mock_subprocess):
    # Create forward channel
    res = await mod.channels_create_forward(ctx,
                                            command="/bin/bash -lc 'echo ready; while true; do read L; echo $L; done'")
    cid = res.channel_id
    assert res.kind == "forward"
    assert isinstance(res.pid, int) and res.pid > 0

    # Status should be connected and ready
    s = await mod.channel_status(ctx, channel_id=cid)
    assert s.kind == "forward"
    assert s.connected is True
    assert s.ready_for_send is True
    assert "pid" in s.details

    # Poll for the "ready" line from the echo script
    evs = await poll_until(ctx, cid, lambda es: any(b"ready" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"ready" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Send a line; expect it echoed back
    await mod.channel_send(ctx, channel_id=cid, mode="text", data="ping", append_newline=True)
    evs = await poll_until(ctx, cid, lambda es: any(b"ping" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"ping" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Close channel
    closed = await mod.channel_close(ctx, channel_id=cid)
    assert closed.success is True

    # After close, channel_status should raise (channel removed)
    with pytest.raises(KeyError):
        await mod.channel_status(ctx, channel_id=cid)


@pytest.mark.asyncio
async def test_poll_timeout_returns_quickly(ctx, mock_subprocess):
    # Create forward channel and poll with short timeout; ensure it doesn't hang
    res = await mod.channels_create_forward(ctx, command="bash -lc true")
    cid = res.channel_id
    out = await mod.channel_poll(ctx, channel_id=cid, timeout=0.010, max_events=10, min_events=1)
    assert isinstance(out.events, list)
    await mod.channel_close(ctx, channel_id=cid)


# Reverse channel tests

@pytest.mark.asyncio
async def test_reverse_connect_duplex_send_both_ways_and_close(ctx):
    r = await mod.channel_create_reverse(ctx, target=None, listener_host="127.0.0.1", listener_port=0)
    cid = r.channel_id
    assert r.listen_port > 0
    assert r.listen_address == "127.0.0.1"

    # Before client connect
    s0 = await mod.channel_status(ctx, channel_id=cid)
    assert s0.connected is False
    assert s0.details.get("listening") == "true"
    assert s0.details.get("port") == str(r.listen_port)

    # Connect a client
    reader, writer = await asyncio.open_connection(r.listen_address, r.listen_port)

    # Wait for server to report 'client_connected'
    evs = await poll_until(ctx, cid,
                           lambda es: any((e.stream == "status" and (e.note or "") == "client_connected") for e in es))
    assert any((e.stream == "status" and (e.note or "") == "client_connected") for e in evs)

    # Server → client
    await mod.channel_send(ctx, channel_id=cid, mode="text", data="srv2cli", append_newline=True)
    line = await asyncio.wait_for(reader.readline(), timeout=1.0)
    assert line.strip() == b"srv2cli"

    # Client → server
    writer.write(b"cli2srv\n")
    await writer.drain()
    evs = await poll_until(ctx, cid, lambda es: any(b"cli2srv" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"cli2srv" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Close server side and then client
    closed = await mod.channel_close(ctx, channel_id=cid)
    assert closed.success is True
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_reverse_send_when_not_connected_returns_zero(ctx):
    r = await mod.channel_create_reverse(ctx, target=None, listener_host="127.0.0.1", listener_port=0)
    cid = r.channel_id
    out = await mod.channel_send(ctx, channel_id=cid, mode="text", data="hello", append_newline=False)
    assert out.bytes_sent == 0
    await mod.channel_close(ctx, channel_id=cid)


# Close-all & cleanup

@pytest.mark.asyncio
async def test_close_all(ctx, mock_subprocess):
    r1 = await mod.channels_create_forward(ctx, command="bash -lc 'echo a'")
    r2 = await mod.channels_create_forward(ctx, command="bash -lc 'echo b'")
    res = await mod.channel_close_all(ctx)
    assert res["closed"] >= 2

    # Any subsequent status on the old channels should fail
    for cid in (r1.channel_id, r2.channel_id):
        with pytest.raises(KeyError):
            await mod.channel_status(ctx, channel_id=cid)
