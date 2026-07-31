from pathlib import Path

import pytest
from persistqueue import Empty

import shyhurricane.persistent_queue as persistent_queue


class FakeQueue:
    def __init__(self, values):
        self.values = list(values)
        self.path = "/tmp/test_queue"
        self.acked = []
        self.clear_calls = []
        self.shrink_calls = 0

    def get(self, block, timeout):
        assert block is True
        assert timeout == 60
        value = self.values.pop(0)
        if value is Empty:
            raise Empty
        return value

    def ack(self, item):
        self.acked.append(item)

    def clear_acked_data(self, max_delete, keep_latest):
        self.clear_calls.append((max_delete, keep_latest))

    def shrink_disk_usage(self):
        self.shrink_calls += 1


def test_active_queue_size_uses_total_unacknowledged_count():
    class Queue:
        def active_size(self):
            return 10

        total = 7

        def unack_count(self):
            return 2

    assert persistent_queue.active_queue_size(Queue()) == 7


def test_active_queue_size_reads_ready_and_processing_rows():
    class Queue:
        total = 10

        def _count(self):
            return 4

        def unack_count(self):
            return 2

    assert persistent_queue.active_queue_size(Queue()) == 6


def test_active_queue_size_falls_back_when_total_is_unavailable():
    class Queue:
        def active_size(self):
            return 3

        def total(self):
            raise NotImplementedError

    assert persistent_queue.active_queue_size(Queue()) == 3


def test_active_queue_size_falls_back_for_non_ack_queue():
    class Queue:
        def active_size(self):
            return 3

    assert persistent_queue.active_queue_size(Queue()) == 3


def test_get_persistent_queue_sanitizes_db_name_and_uses_user_state_dir(monkeypatch, tmp_path):
    captured = {}

    class FakeSQLiteAckQueue:
        def __init__(self, path, auto_commit):
            assert Path(path).is_dir()
            captured["path"] = path
            captured["auto_commit"] = auto_commit

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else Path(path).exists())
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(persistent_queue.persistqueue, "SQLiteAckQueue", FakeSQLiteAckQueue)

    queue = persistent_queue.get_persistent_queue("prod/db:2026", "ingest_queue")

    assert isinstance(queue, FakeSQLiteAckQueue)
    assert captured["auto_commit"] is True
    assert captured["path"] == str(tmp_path / ".local/state/shyhurricane/prod_db_2026/ingest_queue")
    assert (tmp_path / ".local/state/shyhurricane/prod_db_2026/ingest_queue").is_dir()


def test_get_persistent_queue_allows_existing_queue_directory(monkeypatch, tmp_path):
    queue_path = tmp_path / ".local/state/shyhurricane/db/doc_type_queue"
    queue_path.mkdir(parents=True)
    calls = []

    class FakeSQLiteAckQueue:
        def __init__(self, path, auto_commit):
            calls.append((path, auto_commit))

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else Path(path).exists())
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(persistent_queue.persistqueue, "SQLiteAckQueue", FakeSQLiteAckQueue)

    persistent_queue.get_persistent_queue("db", "doc_type_queue")
    persistent_queue.get_persistent_queue("db", "doc_type_queue")

    assert calls == [(str(queue_path), True), (str(queue_path), True)]


def test_get_persistent_queue_rejects_file_at_queue_path(monkeypatch, tmp_path):
    queue_path = tmp_path / ".local/state/shyhurricane/db/doc_type_queue"
    queue_path.parent.mkdir(parents=True)
    queue_path.write_text("not a directory")

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else Path(path).exists())
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)

    with pytest.raises(FileExistsError):
        persistent_queue.get_persistent_queue("db", "doc_type_queue")


def test_persistent_queue_get_acks_none_and_yields_next_item():
    queue = FakeQueue([None, {"id": 1}])

    generator = persistent_queue.persistent_queue_get(queue)

    assert next(generator) == {"id": 1}
    assert queue.acked == [None]


def test_persistent_queue_get_shrinks_after_processed_count(monkeypatch):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue = FakeQueue(["first", "second"])

    generator = persistent_queue.persistent_queue_get(queue, shrink_count=2)

    assert next(generator) == "first"
    assert next(generator) == "second"
    assert queue.clear_calls == [(1000, 0)]
    assert queue.shrink_calls == 1


def test_persistent_queue_get_shrinks_after_idle_timeout(monkeypatch):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    monkeypatch.setattr(persistent_queue.time, "sleep", lambda seconds: None)
    times = iter([0.0, 70.0, 70.0])
    monkeypatch.setattr(persistent_queue.time, "time", lambda: next(times))
    queue = FakeQueue(["first", Empty, "second"])

    generator = persistent_queue.persistent_queue_get(queue, shrink_idle_timeout=60.0)

    assert next(generator) == "first"
    assert next(generator) == "second"
    assert queue.clear_calls == [(1000, 0)]
    assert queue.shrink_calls == 1


def test_shrink_persistent_queue_swallows_queue_errors(monkeypatch):
    class BrokenQueue(FakeQueue):
        def clear_acked_data(self, max_delete, keep_latest):
            raise RuntimeError("database locked")

    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue = BrokenQueue([])

    persistent_queue._shrink_persistent_queue(queue, "broken")

    assert queue.shrink_calls == 0
