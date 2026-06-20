import multiprocessing

import pytest

import shyhurricane.task_queue.types as types
from shyhurricane.task_queue.types import (
    DirBustingQueueItem,
    DirBustingResultItem,
    PortScanQueueItem,
    SaveFindingQueueItem,
    SpiderQueueItem,
    SpiderResultItem,
    TaskPool,
    TaskWorkerIPC,
)


def test_port_scan_queue_item_equality_uses_targets_and_ports_only():
    first = PortScanQueueItem("ctx-1", ["example.com"], ["80"], {"example.com": "127.0.0.1"}, retry=False)
    second = PortScanQueueItem("ctx-2", ["example.com"], ["80"], {}, retry=True)
    different_ports = PortScanQueueItem("ctx-1", ["example.com"], ["443"], {}, retry=False)

    assert first == second
    assert first != different_ports
    assert first != object()


def test_port_scan_queue_item_copy_preserves_values():
    item = PortScanQueueItem("ctx", ["example.com"], [], {"example.com": "127.0.0.1"}, retry=True)

    copied = item.__copy__()

    assert copied is not item
    assert copied.context_id == "ctx"
    assert copied.targets == ["example.com"]
    assert copied.ports == []
    assert copied.additional_hosts == {"example.com": "127.0.0.1"}
    assert copied.retry is True


def test_queue_items_keep_optional_configuration():
    spider = SpiderQueueItem(
        "ctx",
        "https://example.com",
        depth=2,
        user_agent="agent",
        request_headers={"X-Test": "1"},
        additional_hosts={"example.com": "127.0.0.1"},
        cookies={"session": "abc"},
        rate_limit_requests_per_second=3,
    )
    dir_busting = DirBustingQueueItem(
        "ctx",
        "https://example.com",
        method="POST",
        wordlist="/tmp/words.txt",
        extensions=["php"],
        ignored_response_codes=[404],
        params={"debug": "1"},
        mcp_session_volume="volume",
        work_path="/work",
    )
    finding = SaveFindingQueueItem("https://example.com", "# Finding", "Title")

    assert spider.request_headers == {"X-Test": "1"}
    assert spider.cookies == {"session": "abc"}
    assert spider.rate_limit_requests_per_second == 3
    assert dir_busting.method == "POST"
    assert dir_busting.extensions == ["php"]
    assert dir_busting.ignored_response_codes == [404]
    assert dir_busting.params == {"debug": "1"}
    assert dir_busting.mcp_session_volume == "volume"
    assert dir_busting.work_path == "/work"
    assert finding.target == "https://example.com"
    assert finding.markdown == "# Finding"
    assert finding.title == "Title"


def test_result_items_expire_after_thirty_minutes(monkeypatch):
    now = 1_000.0
    monkeypatch.setattr(types.time, "time", lambda: now)
    spider = SpiderResultItem("ctx", http_resource=None)
    dir_busting = DirBustingResultItem("ctx", url=None)

    monkeypatch.setattr(types.time, "time", lambda: now + 1800.1)

    assert spider.is_expired() is True
    assert dir_busting.is_expired() is True


class FakeProcess:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def terminate(self):
        self.calls.append("terminate")
        if self.fail:
            raise RuntimeError("already closed")

    def join(self):
        self.calls.append("join")

    def close(self):
        self.calls.append("close")


def test_task_pool_close_terminates_joins_and_closes_processes():
    first = FakeProcess()
    second = FakeProcess()

    TaskPool([first, second]).close()

    assert first.calls == ["terminate", "join", "close"]
    assert second.calls == ["terminate", "join", "close"]


def test_task_pool_close_continues_when_process_raises():
    broken = FakeProcess(fail=True)
    healthy = FakeProcess()

    TaskPool([broken, healthy]).close()

    assert broken.calls == ["terminate"]
    assert healthy.calls == ["terminate", "join", "close"]


def test_task_worker_ipc_stores_queue_references():
    task_queue = multiprocessing.Queue()
    spider_result_queue = multiprocessing.Queue()
    port_scan_result_queue = multiprocessing.Queue()
    dir_busting_result_queue = multiprocessing.Queue()
    task_pool = TaskPool([])

    try:
        ipc = TaskWorkerIPC(
            task_queue,
            spider_result_queue,
            port_scan_result_queue,
            dir_busting_result_queue,
            task_pool,
        )

        assert ipc.task_queue is task_queue
        assert ipc.spider_result_queue is spider_result_queue
        assert ipc.port_scan_result_queue is port_scan_result_queue
        assert ipc.dir_busting_result_queue is dir_busting_result_queue
        assert ipc.task_pool is task_pool
    finally:
        for queue in [task_queue, spider_result_queue, port_scan_result_queue, dir_busting_result_queue]:
            queue.close()
            queue.join_thread()
