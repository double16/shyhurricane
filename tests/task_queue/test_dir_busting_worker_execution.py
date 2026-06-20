import importlib
import json

from shyhurricane.task_queue.dir_busting_worker import _do_busting, dir_busting_worker
from shyhurricane.task_queue.types import DirBustingQueueItem

worker = importlib.import_module("shyhurricane.task_queue.dir_busting_worker")


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

    def fileno(self):
        return 1

    def readline(self):
        if not self.lines:
            return ""
        return self.lines.pop(0)


class Proc:
    def __init__(self, lines=None, return_code=0, timeout_on_wait=False, immediate_return=False):
        self.stdout = Stdout(lines or [])
        self.return_code = return_code
        self.timeout_on_wait = timeout_on_wait
        self.immediate_return = immediate_return
        self.poll_count = 0

    def wait(self, timeout=None):
        if self.timeout_on_wait:
            raise worker.subprocess.TimeoutExpired("cmd", timeout)
        return self.return_code

    def poll(self):
        self.poll_count += 1
        if self.poll_count <= len(self.stdout.lines):
            return None
        return self.return_code


def katana_line(url="https://example.com/admin"):
    return json.dumps({
        "timestamp": "2025-08-06T11:40:23.555247-05:00",
        "request": {"endpoint": url, "method": "GET", "headers": {}, "body": ""},
        "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "ok"},
    }) + "\n"


def test_dir_busting_worker_delegates_to_do_busting(monkeypatch):
    calls = []
    monkeypatch.setattr(worker, "_do_busting", lambda **kwargs: calls.append(kwargs))
    item = DirBustingQueueItem("ctx", "https://example.com")
    ingest_queue = Queue()
    result_queue = Queue()

    dir_busting_worker(item, ingest_queue, result_queue)

    assert calls[0]["item"] is item
    assert calls[0]["ingest_queue"] is ingest_queue
    assert calls[0]["result_queue"] is result_queue


def test_do_busting_runs_success_path_and_queues_urls(monkeypatch):
    popen_calls = []

    def popen(cmd, **kwargs):
        popen_calls.append(cmd)
        if cmd[:3] == ["docker", "run", "--rm"]:
            return Proc(lines=["noise\n", katana_line()], timeout_on_wait=True)
        if cmd[:2] == ["docker", "exec"]:
            return Proc(return_code=0)
        return Proc(return_code=0)

    monkeypatch.setattr(worker.subprocess, "Popen", popen)
    monkeypatch.setattr(worker.os, "set_blocking", lambda fd, blocking: None)
    monkeypatch.setattr(worker.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(worker.uuid, "uuid4", lambda: type("U", (), {"hex": "abc"})())
    monkeypatch.setattr(worker, "unix_command_image", lambda: "image")
    ingest_queue = Queue()
    result_queue = Queue()
    item = DirBustingQueueItem(
        "ctx",
        "https://example.com/FUZZ",
        ignored_response_codes=[403],
        additional_hosts={"example.com": "127.0.0.1"},
        mcp_session_volume="volume",
        work_path="/work",
    )

    _do_busting(ingest_queue, result_queue, item)

    assert any("--add-host" in call for call in popen_calls)
    assert any("--workdir" in call for call in popen_calls)
    assert ingest_queue.items == [katana_line()]
    assert result_queue.items[0].url == "https://example.com/admin"
    assert result_queue.items[-1].url is None


def test_do_busting_handles_mitmdump_immediate_exit_and_buster_start_failure(monkeypatch):
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: Proc(return_code=1))
    result_queue = Queue()
    _do_busting(Queue(), result_queue, DirBustingQueueItem("ctx", "https://example.com"))
    assert result_queue.items == []

    calls = []

    def popen(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "run", "--rm"]:
            return Proc(timeout_on_wait=True)
        return Proc(return_code=125)

    monkeypatch.setattr(worker.subprocess, "Popen", popen)
    monkeypatch.setattr(worker.time, "sleep", lambda seconds: None)
    result_queue = Queue()
    _do_busting(Queue(), result_queue, DirBustingQueueItem("ctx", "https://example.com"))
    assert result_queue.items[0].url is None
    assert result_queue.items[1].url is None
