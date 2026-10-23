import importlib
import json
from types import SimpleNamespace

import pytest

from shyhurricane.task_queue.spider_worker import _katana_ingest, spider_worker
from shyhurricane.task_queue.types import SpiderQueueItem

spider_module = importlib.import_module("shyhurricane.task_queue.spider_worker")


class Queue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)

    def put_nowait(self, item):
        self.items.append(item)


class Stdout:
    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        if not self.lines:
            return ""
        return self.lines.pop(0)


class Proc:
    def __init__(self, lines, return_code=0):
        self.stdout = Stdout(lines)
        self.return_code = return_code
        self.poll_count = 0

    def poll(self):
        self.poll_count += 1
        if self.poll_count <= len(self.stdout.lines):
            return None
        return self.return_code

    def wait(self):
        return self.return_code


def katana_line(url="https://example.com/", body="<html><head><title>Home</title></head><body></body></html>"):
    return json.dumps({
        "timestamp": "2025-08-06T11:40:23.555247-05:00",
        "request": {"endpoint": url, "method": "GET", "headers": {}, "body": ""},
        "response": {
            "status_code": 200,
            "headers": {"Content-Type": "text/html", "Content-Length": str(len(body))},
            "body": body,
        },
    }) + "\n"


def test_spider_worker_delegates_to_katana_ingest(monkeypatch):
    calls = []
    monkeypatch.setattr(spider_module, "_katana_ingest", lambda **kwargs: calls.append(kwargs))
    item = SpiderQueueItem("ctx", "https://example.com")
    ingest_queue = Queue()
    result_queue = Queue()

    spider_worker(item, ingest_queue, result_queue)

    assert calls[0]["item"] is item
    assert calls[0]["ingest_queue"] is ingest_queue
    assert calls[0]["result_queue"] is result_queue


@pytest.mark.parametrize("rate", [None, 0, 1, 5])
def test_katana_rate_limit_argument(monkeypatch, rate):
    commands = []

    def popen(command, **kwargs):
        commands.append(command)
        return Proc([])

    monkeypatch.setattr(spider_module.subprocess, "Popen", popen)
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    _katana_ingest(SpiderQueueItem("ctx", "http://target.local/", rate_limit_requests_per_second=rate), Queue())
    command = commands[0]
    if rate is None:
        assert "-rate-limit" not in command
    else:
        assert command[command.index("-rate-limit") + 1] == str(3000 if rate == 0 else rate)


def test_katana_ingest_builds_command_indexes_lines_and_queues_resources(monkeypatch):
    popen_calls = []

    def popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return Proc(["ignored\n", katana_line()])

    monkeypatch.setattr(spider_module.subprocess, "Popen", popen)
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    item = SpiderQueueItem(
        "ctx",
        "https://example.com",
        depth=2,
        user_agent="agent",
        request_headers={"X-Test": "yes"},
        cookies={"sid": "abc"},
        additional_hosts={"example.com": "127.0.0.1"},
        rate_limit_requests_per_second=3,
    )
    ingest_queue = Queue()
    result_queue = Queue()

    _katana_ingest(item, ingest_queue, result_queue)

    command = popen_calls[0]
    assert "--add-host" in command
    assert "example.com:127.0.0.1" in command
    assert "-rate-limit" in command
    assert "User-Agent: agent" in command
    assert "X-Test: yes" in command
    assert "Cookie: sid=abc" in command
    assert ingest_queue.items == [katana_line()]
    assert result_queue.items[0].context_id == "ctx"
    assert result_queue.items[0].http_resource.url == "https://example.com/"
    assert result_queue.items[0].http_resource.resource.title == "Home"
    assert result_queue.items[-1].http_resource is None


def test_katana_ingest_handles_parse_errors_and_nonzero_return(monkeypatch):
    monkeypatch.setattr(spider_module.subprocess, "Popen",
                        lambda *args, **kwargs: Proc(['{"request": bad\n'], return_code=2))
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    ingest_queue = Queue()
    result_queue = Queue()

    _katana_ingest(SpiderQueueItem("ctx", "https://example.com"), ingest_queue, result_queue)

    assert ingest_queue.items == ['{"request": bad\n']
    assert result_queue.items[-1].http_resource is None


def test_katana_ingest_without_result_queue_preserves_raw_exchange(monkeypatch):
    line = katana_line()
    monkeypatch.setattr(spider_module.subprocess, "Popen", lambda *args, **kwargs: Proc([line]))
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    ingest_queue = Queue()
    _katana_ingest(SpiderQueueItem("ctx", "https://example.com/"), ingest_queue)
    assert ingest_queue.items == [line]


@pytest.mark.parametrize("body", [None, "const answer = 42;"])
def test_katana_ingest_skips_failed_captures_and_handles_non_html(monkeypatch, body):
    parsed = SimpleNamespace(url="https://example.com/app.js", response_code=200,
                             response_headers={"Content-Type": "application/javascript"},
                             response_body=body, method="GET")
    captures = [SimpleNamespace(url=None, response_code=200),
                SimpleNamespace(url="https://example.com/failed", response_code=0), parsed]
    monkeypatch.setattr(spider_module.subprocess, "Popen", lambda *args, **kwargs: Proc([katana_line()]))
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    monkeypatch.setattr(spider_module, "KatanaDocument",
                        lambda: SimpleNamespace(run=lambda data: {"request_responses": captures}))
    result_queue = Queue()
    _katana_ingest(SpiderQueueItem("ctx", "https://example.com/"), Queue(), result_queue)
    assert len(result_queue.items) == 2
    resource = result_queue.items[0].http_resource
    assert resource.url == "https://example.com/app.js"
    assert resource.resource.title is None
    assert result_queue.items[-1].http_resource is None


def test_katana_ingest_reports_parser_failure_and_signals_completion(monkeypatch, caplog):
    def parse(data):
        raise RuntimeError("parser failed")

    monkeypatch.setattr(spider_module.subprocess, "Popen", lambda *args, **kwargs: Proc([katana_line()]))
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    monkeypatch.setattr(spider_module, "KatanaDocument", lambda: SimpleNamespace(run=parse))
    result_queue = Queue()
    _katana_ingest(SpiderQueueItem("ctx", "https://example.com/"), Queue(), result_queue)
    assert "parser failed" in caplog.text
    assert [item.http_resource for item in result_queue.items] == [None]


def test_katana_ingest_reports_result_queue_failure_and_signals_completion(monkeypatch, caplog):
    class FailingQueue(Queue):
        def put_nowait(self, item):
            if item.http_resource is not None:
                raise RuntimeError("result queue full")
            super().put_nowait(item)

    monkeypatch.setattr(spider_module.subprocess, "Popen", lambda *args, **kwargs: Proc([katana_line()]))
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    result_queue = FailingQueue()
    _katana_ingest(SpiderQueueItem("ctx", "https://example.com/"), Queue(), result_queue)
    assert "result queue full" in caplog.text
    assert [item.http_resource for item in result_queue.items] == [None]


def test_katana_ingest_handles_eof_and_signals_completion(monkeypatch):
    class EofStdout:
        def readline(self):
            raise EOFError

    proc = SimpleNamespace(stdout=EofStdout(), poll=lambda: None, wait=lambda: 0)
    monkeypatch.setattr(spider_module.subprocess, "Popen", lambda *args, **kwargs: proc)
    monkeypatch.setattr(spider_module, "unix_command_image", lambda: "image")
    result_queue = Queue()
    _katana_ingest(SpiderQueueItem("ctx", "https://example.com/"), Queue(), result_queue)
    assert [item.http_resource for item in result_queue.items] == [None]
