import multiprocessing
import signal
from unittest.mock import Mock

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
        self.alive = True

    def terminate(self):
        self.calls.append("terminate")
        if self.fail:
            raise RuntimeError("already closed")

    def is_alive(self):
        return self.alive

    def kill(self):
        self.calls.append("kill")
        self.alive = False

    def join(self, timeout=None):
        self.calls.append("join")
        if not self.fail:
            self.alive = False

    def close(self):
        self.calls.append("close")


def test_task_pool_close_terminates_joins_and_closes_processes():
    first = FakeProcess()
    second = FakeProcess()

    TaskPool([first, second]).close()

    assert first.calls == ["terminate", "join", "join", "close"]
    assert second.calls == ["terminate", "join", "join", "close"]


def test_task_pool_close_continues_when_process_raises():
    broken = FakeProcess(fail=True)
    healthy = FakeProcess()

    TaskPool([broken, healthy]).close()

    assert broken.calls == ["terminate", "join", "kill", "join", "close"]
    assert healthy.calls == ["terminate", "join", "join", "close"]


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


def test_task_pool_graceful_close_and_repeated_cleanup(monkeypatch):
    process = Mock()
    process._shyhurricane_monitor_process_group = False
    process.is_alive.return_value = False
    monkeypatch.setattr(types.time, "monotonic", lambda: 10)
    pool = TaskPool([process])
    pool.close(deadline=310)
    pool.close(deadline=310)
    assert process.join.call_args_list[0].kwargs == {"timeout": 300}
    process.terminate.assert_not_called()
    process.kill.assert_not_called()
    process.close.assert_called_once()


@pytest.mark.parametrize("group_error", [ProcessLookupError, PermissionError])
def test_task_pool_handles_group_signal_errors(monkeypatch, group_error):
    process = Mock(pid=1234)
    process._shyhurricane_monitor_process_group = True
    process.is_alive.side_effect = [True, False] if group_error is ProcessLookupError else [False]
    monkeypatch.setattr(types.os, "killpg", Mock(side_effect=group_error))
    # Skip the polling interval; exercise the final signal and error handling.
    ticks = iter([10, 20, 20])
    monkeypatch.setattr(types.time, "monotonic", lambda: next(ticks))
    TaskPool([process]).close()
    if group_error is ProcessLookupError:
        process.terminate.assert_called_once()
    process.close.assert_called_once()


def test_task_pool_kills_unresponsive_group_after_term(monkeypatch):
    process = Mock(pid=1234)
    process._shyhurricane_monitor_process_group = True
    process.is_alive.return_value = True
    signals = []
    clock = [0.0]
    monkeypatch.setattr(types.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(types.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    monkeypatch.setattr(types.os, "killpg", lambda pid, sig: signals.append(sig))
    TaskPool([process]).close(deadline=0)
    assert signals[0] == signal.SIGTERM
    assert signals[-1] == signal.SIGKILL
    assert clock[0] >= 5
    process.kill.assert_called_once()
    process.close.assert_called_once()


def test_task_pool_continues_cleanup_after_join_and_close_errors(monkeypatch):
    broken = Mock()
    broken._shyhurricane_monitor_process_group = False
    broken.join.side_effect = RuntimeError("join failed")
    broken.close.side_effect = RuntimeError("close failed")
    healthy = Mock()
    healthy._shyhurricane_monitor_process_group = False
    healthy.is_alive.return_value = False
    TaskPool([broken, healthy]).close(deadline=0)
    healthy.close.assert_called_once()


def test_nested_worker_does_not_create_process_group(monkeypatch):
    monkeypatch.setenv("SHYHURRICANE_MONITOR", "1")
    setsid = Mock()
    monkeypatch.setattr(types.os, "setsid", setsid)
    monkeypatch.setattr(types.os, "dup2", Mock())
    monkeypatch.setattr(types.signal, "signal", Mock())
    types.prepare_worker_process(create_process_group=False)
    setsid.assert_not_called()


def test_worker_process_group_setup_failure_is_logged(monkeypatch, caplog):
    monkeypatch.delenv("SHYHURRICANE_MONITOR", raising=False)
    monkeypatch.setattr(types.os, "setsid", Mock(side_effect=OSError("unavailable")))
    types.prepare_worker_process()
    assert "Failed to create worker process group" in caplog.text
