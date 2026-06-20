import importlib
import json

import shyhurricane.task_queue.spider_worker as spider_worker_export
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
