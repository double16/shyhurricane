import base64
import binascii
import pickle
import sqlite3
from pathlib import Path

import pytest
from haystack import Document
from persistqueue import Empty, SQLiteAckQueue

import shyhurricane.persistent_queue as persistent_queue
from shyhurricane.task_queue.types import SaveFindingQueueItem


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
    original_exists = persistent_queue.os.path.exists

    class FakeSQLiteAckQueue:
        def __init__(self, path, auto_commit, serializer):
            assert Path(path).is_dir()
            captured["path"] = path
            captured["auto_commit"] = auto_commit
            captured["serializer"] = serializer

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else original_exists(path))
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(persistent_queue.persistqueue, "SQLiteAckQueue", FakeSQLiteAckQueue)

    queue = persistent_queue.get_persistent_queue("prod/db:2026", "ingest_queue")

    assert isinstance(queue, FakeSQLiteAckQueue)
    assert captured["auto_commit"] is True
    assert captured["serializer"] is persistent_queue.Base64QueueSerializer
    assert captured["path"] == str(tmp_path / ".local/state/shyhurricane/prod_db_2026/ingest_queue")
    assert (tmp_path / ".local/state/shyhurricane/prod_db_2026/ingest_queue").is_dir()


def test_scan_finding_queue_survives_reopen(tmp_path):
    path = str(tmp_path / "scan_finding_queue")
    queue = SQLiteAckQueue(path=path, auto_commit=True, serializer=persistent_queue.Base64QueueSerializer)
    queue.put(SaveFindingQueueItem("https://example.com/a.js", "# finding", "Scan", "stable-id"))
    queue.close()

    reopened = SQLiteAckQueue(path=path, auto_commit=True, serializer=persistent_queue.Base64QueueSerializer)
    item = reopened.get(block=False)
    assert item.finding_id == "stable-id"
    assert item.target == "https://example.com/a.js"
    reopened.ack(item)
    reopened.close()


def test_get_persistent_queue_allows_existing_queue_directory(monkeypatch, tmp_path):
    queue_path = tmp_path / ".local/state/shyhurricane/db/doc_type_queue"
    queue_path.mkdir(parents=True)
    calls = []
    original_exists = persistent_queue.os.path.exists

    class FakeSQLiteAckQueue:
        def __init__(self, path, auto_commit, serializer):
            assert serializer is persistent_queue.Base64QueueSerializer
            calls.append((path, auto_commit))

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else original_exists(path))
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(persistent_queue.persistqueue, "SQLiteAckQueue", FakeSQLiteAckQueue)

    persistent_queue.get_persistent_queue("db", "doc_type_queue")
    persistent_queue.get_persistent_queue("db", "doc_type_queue")

    assert calls == [(str(queue_path), True), (str(queue_path), True)]


def test_get_persistent_queue_rejects_file_at_queue_path(monkeypatch, tmp_path):
    queue_path = tmp_path / ".local/state/shyhurricane/db/doc_type_queue"
    queue_path.parent.mkdir(parents=True)
    queue_path.write_text("not a directory")
    original_exists = persistent_queue.os.path.exists

    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else original_exists(path))
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


@pytest.mark.parametrize("value", [
    "", "héllo 🌪", b"\x00\xff\x80", {"response": "body", "headers": ["x-test"]}, None,
    Document(content="indexed body", meta={"url": "https://example.com"}),
    SaveFindingQueueItem("https://example.com", "# finding", "Title", "stable-id"),
])
def test_base64_serializer_round_trips_original_objects(value):
    encoded = persistent_queue.Base64QueueSerializer.dumps(value)
    assert base64.b64decode(encoded, validate=True) == pickle.dumps(value, protocol=4)
    restored = persistent_queue.Base64QueueSerializer.loads(encoded)
    assert type(restored) is type(value)
    assert pickle.dumps(restored, protocol=4) == pickle.dumps(value, protocol=4)


def test_base64_serializer_reads_legacy_pickle():
    value = {"body": b"\x00\xff", "text": "héllo"}
    assert persistent_queue.Base64QueueSerializer.loads(pickle.dumps(value, protocol=4)) == value


@pytest.mark.parametrize("data,error", [
    (b"not base64!", binascii.Error),
    (b"YWJj\n", binascii.Error),
    (b"YQ", binascii.Error),
    (base64.b64encode(b"not pickle"), pickle.UnpicklingError),
    (b"\x80\x04invalid", pickle.UnpicklingError),
])
def test_base64_serializer_rejects_corrupt_payloads(data, error):
    with pytest.raises(error):
        persistent_queue.Base64QueueSerializer.loads(data)


@pytest.mark.parametrize("factory", [
    persistent_queue.get_ingest_queue,
    persistent_queue.get_doc_type_queue,
    persistent_queue.get_scan_finding_queue,
])
def test_queue_factories_store_base64_and_reopen(monkeypatch, tmp_path, factory):
    original_exists = persistent_queue.os.path.exists
    monkeypatch.setattr(persistent_queue.os.path, "exists",
                        lambda path: False if path == "/data" else original_exists(path))
    monkeypatch.setattr(persistent_queue.Path, "home", lambda: tmp_path)
    value = {"body": "héllo", "binary": b"\xff"}
    queue = factory("db")
    queue.put(value)
    path = queue.path
    queue.close()

    with sqlite3.connect(Path(path) / "data.db") as connection:
        data, = connection.execute("SELECT data FROM ack_queue_default").fetchone()
    assert base64.b64decode(data, validate=True) == pickle.dumps(value, protocol=4)

    reopened = factory("db")
    try:
        item = reopened.get(block=False)
        assert item == value
        reopened.ack(item)
        assert reopened.acked_count() == 1
    finally:
        reopened.close()


def test_base64_queue_handles_mixed_records_updates_and_acknowledgements(tmp_path):
    path = str(tmp_path / "mixed")
    legacy = SQLiteAckQueue(path=path, auto_commit=True)
    legacy_id = legacy.put({"format": "legacy"})
    legacy.close()

    queue = SQLiteAckQueue(path=path, auto_commit=True, serializer=persistent_queue.Base64QueueSerializer)
    try:
        queue.put({"format": "new"})
        old = queue.get(block=False)
        assert old == {"format": "legacy"}
        queue.nack(old)
        retried = queue.get(block=False)
        assert retried == old
        queue.update({"format": "updated"}, id=legacy_id)
        queue.nack(retried)
        updated = queue.get(block=False)
        assert updated == {"format": "updated"}
        queue.ack(updated)
        new = queue.get(block=False)
        assert new == {"format": "new"}
        queue.ack_failed(new)
        assert queue.acked_count() == 1
        assert queue.ack_failed_count() == 1
        with sqlite3.connect(Path(path) / "data.db") as connection:
            rows = connection.execute("SELECT data FROM ack_queue_default ORDER BY _id").fetchall()
        assert [pickle.loads(base64.b64decode(row[0], validate=True)) for row in rows] == [
            {"format": "updated"}, {"format": "new"},
        ]
        with pytest.raises(Empty):
            queue.get(block=False)
    finally:
        queue.close()


def test_base64_queue_resumes_unacknowledged_document_after_reopen(tmp_path):
    path = str(tmp_path / "documents")
    document = Document(content="indexed body", meta={"url": "https://example.com"})
    queue = SQLiteAckQueue(path=path, auto_commit=True, serializer=persistent_queue.Base64QueueSerializer)
    queue.put(document)
    assert queue.get(block=False) == document
    queue.close()
    reopened = SQLiteAckQueue(path=path, auto_commit=True, serializer=persistent_queue.Base64QueueSerializer)
    try:
        item = reopened.get(block=False)
        assert item == document
        reopened.ack(item)
        assert reopened.acked_count() == 1
    finally:
        reopened.close()
