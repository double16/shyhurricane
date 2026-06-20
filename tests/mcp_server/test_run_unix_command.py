import pytest
from mcp import McpError

import shyhurricane.mcp_server.run_unix_command as run_unix
from shyhurricane.mcp_server.run_unix_command import OutputLimiter, _run_unix_command, _write_stream_to_file


class FakeAsyncStream:
    def __init__(self, lines):
        self.lines = list(lines)

    async def readline(self):
        if not self.lines:
            return b""
        return self.lines.pop(0)


class FakeAsyncFile:
    def __init__(self):
        self.writes = []

    async def write(self, data):
        self.writes.append(data)


def test_output_limiter_without_limit_never_fills():
    limiter = OutputLimiter(None)

    assert limiter.inc(10) == 10
    assert limiter.inc(5) == 15
    assert limiter.is_full() is False


def test_output_limiter_fills_only_after_limit_is_exceeded():
    limiter = OutputLimiter(5)

    assert limiter.inc(5) == 5
    assert limiter.is_full() is False
    assert limiter.inc(1) == 6
    assert limiter.is_full() is True


@pytest.mark.asyncio
async def test_write_stream_to_file_stops_writing_after_limit_is_exceeded():
    stream = FakeAsyncStream([b"abc\n", b"def\n", b"ghi\n"])
    file = FakeAsyncFile()
    limiter = OutputLimiter(5)

    await _write_stream_to_file(stream, file, limiter)

    assert file.writes == [b"abc\n"]
    assert limiter.length == 12
    assert limiter.is_full() is True


@pytest.mark.asyncio
async def test_write_stream_to_file_writes_all_lines_without_limit():
    stream = FakeAsyncStream([b"one\n", b"two\n"])
    file = FakeAsyncFile()

    await _write_stream_to_file(stream, file, OutputLimiter(None))

    assert file.writes == [b"one\n", b"two\n"]


class LifespanContext:
    work_path = "/work/session"


class RequestContext:
    lifespan_context = LifespanContext()


class Ctx:
    request_context = RequestContext()


class ServerContext:
    def __init__(self, open_world):
        self.open_world = open_world
        self.mcp_session_volume = "volume"


class Stdin:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    def close(self):
        self.closed = True


class Proc:
    def __init__(self, return_code, stdout_lines, stderr_lines):
        self.return_code = return_code
        self.stdin = Stdin()
        self.stdout = FakeAsyncStream(stdout_lines)
        self.stderr = FakeAsyncStream(stderr_lines)

    async def wait(self):
        return self.return_code


@pytest.mark.asyncio
async def test_run_unix_command_rejects_blank_command():
    with pytest.raises(McpError):
        await _run_unix_command(Ctx(), "   ", {})


@pytest.mark.asyncio
async def test_run_unix_command_builds_open_world_docker_command_and_returns_success(monkeypatch):
    proc = Proc(0, [b"hello\n"], [b"warning\n"])
    captured = {}

    async def create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return proc

    async def get_server_context():
        return ServerContext(open_world=True)

    async def log_history(*args, **kwargs):
        captured["history"] = kwargs or args

    monkeypatch.setattr(run_unix, "get_server_context", get_server_context)
    monkeypatch.setattr(run_unix, "get_additional_hosts", lambda ctx, hosts=None: hosts or {})
    monkeypatch.setattr(run_unix, "unix_command_image", lambda: "image")
    monkeypatch.setattr(run_unix, "log_history", log_history)
    monkeypatch.setattr(run_unix.asyncio, "create_subprocess_exec", create_subprocess_exec)

    result = await _run_unix_command(
        Ctx(),
        "echo hello",
        {"example.com": "127.0.0.1"},
        stdin="input",
        env={"A": "B"},
        capture_output_to_file=True,
    )

    assert result.return_code == 0
    assert result.output == "hello"
    assert result.error == ""
    assert result.output_file.endswith(".out")
    assert result.error_file.endswith(".err")
    assert "--cap-add" in captured["cmd"]
    assert "--add-host" in captured["cmd"]
    assert "example.com:127.0.0.1" in captured["cmd"]
    assert "-i" in captured["cmd"]
    assert "-e" in captured["cmd"]
    assert "A=B" in captured["cmd"]
    assert proc.stdin.data == b"input"
    assert proc.stdin.closed is True


@pytest.mark.asyncio
async def test_run_unix_command_closed_world_error_prefers_stderr(monkeypatch):
    proc = Proc(2, [b"stdout-too-long\n"], [b"stderr\n"])

    async def create_subprocess_exec(*cmd, **kwargs):
        return proc

    async def get_server_context():
        return ServerContext(open_world=False)

    async def log_history(*args, **kwargs):
        return None

    monkeypatch.setattr(run_unix, "get_server_context", get_server_context)
    monkeypatch.setattr(run_unix, "get_additional_hosts", lambda ctx, hosts=None: {})
    monkeypatch.setattr(run_unix, "unix_command_image", lambda: "image")
    monkeypatch.setattr(run_unix, "log_history", log_history)
    monkeypatch.setattr(run_unix.asyncio, "create_subprocess_exec", create_subprocess_exec)

    result = await _run_unix_command(Ctx(), "timeout 1 false", {}, output_length_limit=8)

    assert result.return_code == 2
    assert result.output == ""
    assert result.output_truncated is True
    assert result.error.strip() == "stderr"
    assert result.notes == run_unix.open_world_command_disable_notes
