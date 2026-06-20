import pytest

import shyhurricane.task_queue as task_queue
from shyhurricane.task_queue.types import (
    DirBustingQueueItem,
    PortScanQueueItem,
    SaveFindingQueueItem,
    SpiderQueueItem,
)


class FakeQueue:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.closed = False

    def get(self):
        if not self.items:
            raise KeyboardInterrupt
        return self.items.pop(0)

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, target=None, kwargs=None):
        self.target = target
        self.kwargs = kwargs
        self.started = False

    def start(self):
        self.started = True


def test_start_task_worker_creates_queues_and_processes(monkeypatch):
    created_processes = []

    def process_factory(target=None, kwargs=None):
        process = FakeProcess(target=target, kwargs=kwargs)
        created_processes.append(process)
        return process

    monkeypatch.setattr(task_queue.multiprocessing, "Queue", FakeQueue)
    monkeypatch.setattr(task_queue, "Process", process_factory)
    monkeypatch.setattr(task_queue, "get_generator_config", lambda: "generator")

    ipc = task_queue.start_task_worker("db", "/tmp/queue", pool_size=2)

    assert len(created_processes) == 2
    assert all(process.started for process in created_processes)
    assert created_processes[0].kwargs["db"] == "db"
    assert created_processes[0].kwargs["ingest_queue_path"] == "/tmp/queue"
    assert ipc.task_pool.processes == created_processes


def test_start_task_worker_rejects_zero_pool_size():
    with pytest.raises(AssertionError):
        task_queue.start_task_worker("db", "/tmp/queue", pool_size=0)


def test_task_router_dispatches_all_known_items(monkeypatch):
    calls = []
    task_items = [
        SpiderQueueItem("ctx", "https://example.com"),
        PortScanQueueItem("ctx", ["example.com"], ["80"], {}, False),
        DirBustingQueueItem("ctx", "https://example.com"),
        SaveFindingQueueItem("example.com", "# finding", "Title"),
    ]

    class AckQueue(FakeQueue):
        def __init__(self, path, auto_commit):
            super().__init__()
            self.path = path
            self.auto_commit = auto_commit

    class DocTypeQueue(FakeQueue):
        pass

    class PortScanContext:
        def __init__(self, db, embedder_cache):
            calls.append(("port_ctx", db, embedder_cache.__class__.__name__))

        def warm_up(self):
            calls.append(("port_warm",))

    class FindingContext:
        def __init__(self, db, generator_config, embedder_cache, doc_type_queue):
            calls.append(("finding_ctx", db, generator_config, doc_type_queue.__class__.__name__))

        def warm_up(self):
            calls.append(("finding_warm",))

    monkeypatch.setattr(task_queue.faulthandler, "register", lambda signal: None)
    monkeypatch.setattr(task_queue.atexit, "register", lambda func: None)
    monkeypatch.setattr(task_queue.persistqueue, "SQLiteAckQueue", AckQueue)
    monkeypatch.setattr(task_queue, "get_doc_type_queue", lambda db: DocTypeQueue())
    monkeypatch.setattr(task_queue, "PortScanContext", PortScanContext)
    monkeypatch.setattr(task_queue, "FindingContext", FindingContext)
    monkeypatch.setattr(task_queue, "spider_worker",
                        lambda item, ingest_queue, result_queue: calls.append(("spider", item.uri)))
    monkeypatch.setattr(task_queue, "port_scan_worker",
                        lambda ctx, item, result_queue: calls.append(("port", item.targets)))
    monkeypatch.setattr(task_queue, "dir_busting_worker",
                        lambda item, ingest_queue, result_queue: calls.append(("dir", item.uri)))
    monkeypatch.setattr(task_queue, "save_finding_worker", lambda ctx, item: calls.append(("finding", item.title)))

    task_queue._task_router(
        db="db",
        ingest_queue_path="/tmp/ingest",
        task_queue=FakeQueue(task_items),
        spider_result_queue=FakeQueue(),
        port_scan_result_queue=FakeQueue(),
        dir_busting_result_queue=FakeQueue(),
        generator_config="generator",
    )

    assert ("spider", "https://example.com") in calls
    assert ("port", ["example.com"]) in calls
    assert ("dir", "https://example.com") in calls
    assert ("finding", "Title") in calls
    assert calls.count(("port_warm",)) == 1
    assert calls.count(("finding_warm",)) == 1
