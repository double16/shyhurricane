import queue

import pytest

import shyhurricane.mcp_server.tools.directory_buster as directory
from shyhurricane.task_queue import DirBustingResultItem


async def noop(*args, **kwargs):
    return None


class LifespanContext:
    app_context_id = "ctx-1"
    work_path = "/work"


class RequestContext:
    lifespan_context = LifespanContext()


class Ctx:
    request_context = RequestContext()

    def __init__(self):
        self.messages = []

    async def info(self, message):
        self.messages.append(message)


class Queue:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.put_items = []

    def put(self, item, block=True):
        self.put_items.append(item)

    def get(self, timeout):
        if not self.items:
            raise queue.Empty
        return self.items.pop(0)


class ServerContext:
    open_world = True
    mcp_session_volume = "volume"

    def __init__(self, results=None):
        self.task_queue = Queue()
        self.dir_busting_result_queue = Queue(results)


def patch_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(directory, "get_server_context", get_fake_server_context)
    monkeypatch.setattr(directory, "log_tool_history", noop)
    monkeypatch.setattr(directory, "get_additional_hosts", lambda ctx, additional=None: additional or {})
    monkeypatch.setattr(directory, "get_additional_http_headers", lambda ctx, headers=None: headers or {})
    monkeypatch.setattr(directory, "get_rate_limit_requests_per_second", lambda url: 7)


def test_dirbuster_instructions():
    assert directory.dirbuster_instructions([], False) == directory.dirbuster_results_instructions_not_found
    assert directory.dirbuster_instructions(["https://example.com/admin"], False) == (
        directory.dirbuster_results_instructions_found
    )
    assert directory.dirbuster_instructions(["https://example.com/admin"], True).endswith(
        directory.dirbuster_results_instructions_has_more
    )


@pytest.mark.asyncio
async def test_validate_wordlist_accepts_existing_local_file(monkeypatch):
    class Result:
        return_code = 0

    async def run_command(*args, **kwargs):
        return Result()

    monkeypatch.setattr(directory, "_run_unix_command", run_command)

    assert await directory.validate_wordlist(None, "/tmp/words.txt") == "/tmp/words.txt"


@pytest.mark.asyncio
async def test_validate_wordlist_corrects_to_found_wordlist(monkeypatch):
    class Result:
        return_code = 1

    async def run_command(*args, **kwargs):
        return Result()

    async def find_wordlists(ctx, name, limit):
        return ["/usr/share/wordlists/words.txt"]

    monkeypatch.setattr(directory, "_run_unix_command", run_command)
    monkeypatch.setattr(directory, "find_wordlists", find_wordlists)

    assert await directory.validate_wordlist(None, "/tmp/words.txt") == "/usr/share/wordlists/words.txt"


@pytest.mark.asyncio
async def test_directory_buster_queues_work_and_collects_results(monkeypatch):
    other = DirBustingResultItem("other", "https://other.test")
    done = DirBustingResultItem("ctx-1", None)
    found = DirBustingResultItem("ctx-1", "https://example.com/admin")
    server_context = ServerContext([other, found, done])
    patch_context(monkeypatch, server_context)

    async def validate_wordlist(ctx, wordlist):
        return wordlist

    monkeypatch.setattr(directory, "validate_wordlist", validate_wordlist)

    ctx = Ctx()
    result = await directory.directory_buster(
        ctx,
        " https://example.com/FUZZ ",
        depth=9,
        wordlist="/tmp/words.txt",
        extensions=".php",
        ignored_response_codes="404",
        cookies="a=b",
        params="x=1",
        request_headers="X-Test: yes",
        timeout_seconds=30,
    )

    queued = server_context.task_queue.put_items[0]
    assert queued.uri == "https://example.com/FUZZ"
    assert queued.depth == 5
    assert queued.extensions == ["php"]
    assert queued.ignored_response_codes == [404]
    assert queued.cookies == {"a": "b"}
    assert queued.params == {"x": "1"}
    assert queued.rate_limit_requests_per_second == 7
    assert server_context.dir_busting_result_queue.put_items[0].context_id == "other"
    assert result.urls == ["https://example.com/admin"]
    assert result.has_more is False
    assert ctx.messages == ["Found: https://example.com/admin"]
