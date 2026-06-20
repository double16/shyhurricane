import json

from haystack import Document

import shyhurricane.index.web_resources as web_resources


class Queue:
    def __init__(self):
        self.acked = []
        self.failed = []
        self.items = []
        self.closed = False
        self.resumed = False

    def resume_unack_tasks(self):
        self.resumed = True

    def close(self):
        self.closed = True

    def put(self, item):
        self.items.append(item)

    def ack(self, item):
        self.acked.append(item)

    def ack_failed(self, item):
        self.failed.append(item)


class Pipeline:
    def __init__(self, output=None, exc=None):
        self.output = output or {}
        self.exc = exc
        self.calls = []

    def run(self, data):
        self.calls.append(data)
        if self.exc:
            raise self.exc
        return self.output


def finite_queue(items):
    for item in items:
        yield item
    raise KeyboardInterrupt


def test_ingest_worker_acks_and_queues_content_documents(monkeypatch, tmp_path):
    ingest_queue = Queue()
    doc_type_queue = Queue()
    doc = Document(content="body", meta={"type": "content"})
    pipeline = Pipeline({"output": {"documents": [doc, Document(content="n", meta={"type": "network"})]}})
    item = json.dumps({"request": {"endpoint": "https://example.com"}})

    monkeypatch.setattr(web_resources.faulthandler, "register", lambda *args, **kwargs: None)
    monkeypatch.setattr(web_resources, "get_ingest_queue", lambda db: ingest_queue)
    monkeypatch.setattr(web_resources, "get_doc_type_queue", lambda db: doc_type_queue)
    monkeypatch.setattr(web_resources, "get_log_path", lambda db, name: tmp_path / name)
    monkeypatch.setattr(web_resources, "build_ingest_pipeline", lambda **kwargs: pipeline)
    monkeypatch.setattr(web_resources, "persistent_queue_get", lambda queue, shrink_count: finite_queue([item]))

    web_resources._ingest_worker("db", object())

    assert ingest_queue.resumed is True
    assert ingest_queue.acked == [item]
    assert ingest_queue.failed == []
    assert doc_type_queue.items == [doc]
    assert (tmp_path / "index.txt").read_text() == item + "\n"


def test_ingest_worker_marks_failures(monkeypatch):
    ingest_queue = Queue()
    doc_type_queue = Queue()
    item = "{not-json"

    monkeypatch.setattr(web_resources.faulthandler, "register", lambda *args, **kwargs: None)
    monkeypatch.setattr(web_resources, "get_ingest_queue", lambda db: ingest_queue)
    monkeypatch.setattr(web_resources, "get_doc_type_queue", lambda db: doc_type_queue)
    monkeypatch.setattr(web_resources, "get_log_path", lambda db, name: None)
    monkeypatch.setattr(web_resources, "build_ingest_pipeline", lambda **kwargs: Pipeline(exc=RuntimeError("boom")))
    monkeypatch.setattr(web_resources, "persistent_queue_get", lambda queue, shrink_count: finite_queue([item]))

    web_resources._ingest_worker("db", object())

    assert ingest_queue.acked == []
    assert ingest_queue.failed == [item]
    assert doc_type_queue.items == []


def test_doc_type_worker_success_failure_and_bad_state(monkeypatch):
    queue = Queue()
    first = Document(content="ok", meta={"url": "https://example.com/ok"}, id="ok")
    second = Document(content="bad", meta={"url": "https://example.com/bad"}, id="bad")
    pipeline = Pipeline()

    def run(data):
        if data["input"]["documents"][0] is second:
            raise RuntimeError("failed")
        return {}

    pipeline.run = run
    bad_state_calls = iter([True])

    monkeypatch.setattr(web_resources.faulthandler, "register", lambda *args, **kwargs: None)
    monkeypatch.setattr(web_resources, "get_doc_type_queue", lambda db: queue)
    monkeypatch.setattr(web_resources, "build_doc_type_pipeline", lambda **kwargs: pipeline)
    monkeypatch.setattr(web_resources, "persistent_queue_get", lambda q, shrink_count: finite_queue([second, first]))
    monkeypatch.setattr(web_resources, "log_heap_stats", lambda: None)
    monkeypatch.setattr(web_resources, "log_gpu_memory_summary", lambda: None)
    monkeypatch.setattr(web_resources, "is_current_process_in_bad_state", lambda: next(bad_state_calls))

    assert web_resources._doc_type_worker("db", object()) == 0
    assert queue.failed == [second]
    assert queue.acked == [first]


def test_start_ingest_worker_respects_low_power(monkeypatch):
    processes = []
    queue = Queue()

    class Config:
        low_power = True

    class Process:
        def __init__(self, target, args):
            self.target = target
            self.args = args
            self.started = False
            processes.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(web_resources, "get_server_config", lambda: Config())
    monkeypatch.setattr(web_resources.multiprocessing, "Process", Process)
    monkeypatch.setattr(web_resources, "get_ingest_queue", lambda db: queue)

    returned_queue, pool = web_resources.start_ingest_worker("db", object(), pool_size=3)

    assert returned_queue is queue
    assert len(processes) == 1
    assert processes[0].target is web_resources._ingest_worker
    assert len(pool.processes) == 1


def test_start_ingest_worker_starts_doc_type_watchers_when_enabled(monkeypatch):
    processes = []
    queue = Queue()

    class Config:
        low_power = False

    class Process:
        def __init__(self, target, args):
            self.target = target
            self.args = args
            processes.append(self)

        def start(self):
            pass

    monkeypatch.setattr(web_resources, "get_server_config", lambda: Config())
    monkeypatch.setattr(web_resources.multiprocessing, "Process", Process)
    monkeypatch.setattr(web_resources, "get_ingest_queue", lambda db: queue)

    _, pool = web_resources.start_ingest_worker("db", object(), pool_size=2)

    assert [p.target for p in processes] == [
        web_resources._doc_type_watcher,
        web_resources._doc_type_watcher,
        web_resources._ingest_worker,
    ]
    assert len(pool.processes) == 3


def test_doc_type_watcher_restarts_on_zero_exit_and_closes(monkeypatch):
    processes = []
    exitcodes = iter([0, 1])

    class Process:
        def __init__(self, target, args):
            self.target = target
            self.args = args
            self.exitcode = next(exitcodes)
            self.terminated = False
            self.closed = False
            processes.append(self)

        def start(self):
            pass

        def join(self):
            pass

        def terminate(self):
            self.terminated = True

        def close(self):
            self.closed = True

    monkeypatch.setattr(web_resources.faulthandler, "register", lambda *args, **kwargs: None)
    monkeypatch.setattr(web_resources.multiprocessing, "Process", Process)

    web_resources._doc_type_watcher("db", object())

    assert len(processes) == 2
    assert all(process.closed for process in processes)


def test_bad_state_detects_mps_memory(monkeypatch):
    class MpsBackend:
        @staticmethod
        def is_available():
            return True

    class Backends:
        mps = MpsBackend()

    class Mps:
        @staticmethod
        def driver_allocated_memory():
            return 20

        @staticmethod
        def recommended_max_memory():
            return 10

    monkeypatch.setattr(web_resources.torch, "backends", Backends())
    monkeypatch.setattr(web_resources.torch, "mps", Mps())

    assert web_resources.is_current_process_in_bad_state() is True


def test_bad_state_handles_missing_mps_memory_apis(monkeypatch):
    class MpsBackend:
        @staticmethod
        def is_available():
            return True

    class Backends:
        mps = MpsBackend()

    class Mps:
        @staticmethod
        def driver_allocated_memory():
            raise AttributeError("unsupported")

    monkeypatch.setattr(web_resources.torch, "backends", Backends())
    monkeypatch.setattr(web_resources.torch, "mps", Mps())

    assert web_resources.is_current_process_in_bad_state() is False
