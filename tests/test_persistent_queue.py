import asyncio
import base64
import binascii
import pickle
import sqlite3
import threading
import zlib
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock, Mock

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
        self.tran_lock = threading.Lock()
        self._putter = MagicMock()
        self._putter.execute.return_value.fetchone.return_value = (16384, 65536, 4096)

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

    def acked_count(self):
        return 1500

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
        def __init__(self, path, auto_commit, serializer, auto_resume):
            assert auto_resume is True
            self.tran_lock = threading.Lock()
            self._putter = MagicMock()
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
        def __init__(self, path, auto_commit, serializer, auto_resume):
            assert auto_resume is True
            self.tran_lock = threading.Lock()
            self._putter = MagicMock()
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
    queue = FakeQueue(["first", "second", "third"])

    generator = persistent_queue.persistent_queue_get(queue, shrink_count=2)

    assert next(generator) == "first"
    assert next(generator) == "second"
    assert queue.clear_calls == []
    assert next(generator) == "third"
    assert queue.clear_calls == [(1500, 200)]
    assert queue.shrink_calls == 1


def test_persistent_queue_get_shrinks_after_idle_timeout(monkeypatch):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    monkeypatch.setattr(persistent_queue.time, "sleep", lambda seconds: None)
    clock = [0.0]
    monkeypatch.setattr(persistent_queue.time, "monotonic", lambda: clock[0])
    queue = FakeQueue(["first", Empty, "second"])

    generator = persistent_queue.persistent_queue_get(queue, shrink_idle_timeout=60.0)

    assert next(generator) == "first"
    clock[0] = 70.0
    assert next(generator) == "second"
    assert queue.clear_calls == [(1500, 200)]
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
    payload = base64.b64decode(encoded, validate=True)
    assert payload.startswith(b"SHQ\x01ZLIB\x00")
    assert zlib.decompress(payload[len(persistent_queue.QUEUE_COMPRESSION_MARKER):]) == pickle.dumps(value, protocol=4)
    restored = persistent_queue.Base64QueueSerializer.loads(encoded)
    assert type(restored) is type(value)
    assert pickle.dumps(restored, protocol=4) == pickle.dumps(value, protocol=4)


def test_base64_serializer_reads_legacy_pickle():
    value = {"body": b"\x00\xff", "text": "héllo"}
    assert persistent_queue.Base64QueueSerializer.loads(pickle.dumps(value, protocol=4)) == value


def test_base64_serializer_reads_uncompressed_base64_without_decompression(monkeypatch):
    value = {"body": b"\x00\xff", "text": "héllo"}
    monkeypatch.setattr(zlib, "decompress", lambda data: pytest.fail("Unmarked records must not be decompressed"))
    assert persistent_queue.Base64QueueSerializer.loads(base64.b64encode(pickle.dumps(value, protocol=4))) == value


def test_base64_serializer_reduces_repetitive_payload_size():
    value = {"body": "<p>Repeated response content</p>" * 10000}
    encoded = persistent_queue.Base64QueueSerializer.dumps(value)
    assert len(encoded) < len(base64.b64encode(pickle.dumps(value, protocol=4)))
    assert persistent_queue.Base64QueueSerializer.loads(encoded) == value


@pytest.mark.parametrize("data,error", [
    (b"not base64!", binascii.Error),
    (b"YWJj\n", binascii.Error),
    (b"YQ", binascii.Error),
    (base64.b64encode(b"not pickle"), pickle.UnpicklingError),
    (b"\x80\x04invalid", pickle.UnpicklingError),
    (base64.b64encode(persistent_queue.QUEUE_COMPRESSION_MARKER), zlib.error),
    (base64.b64encode(persistent_queue.QUEUE_COMPRESSION_MARKER + b"not compressed"), zlib.error),
    (base64.b64encode(persistent_queue.QUEUE_COMPRESSION_MARKER + zlib.compress(b"data")[:-1]), zlib.error),
    (base64.b64encode(persistent_queue.QUEUE_COMPRESSION_MARKER + zlib.compress(b"not pickle")),
     pickle.UnpicklingError),
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
    payload = base64.b64decode(data, validate=True)
    assert payload.startswith(persistent_queue.QUEUE_COMPRESSION_MARKER)
    assert zlib.decompress(payload[len(persistent_queue.QUEUE_COMPRESSION_MARKER):]) == pickle.dumps(value, protocol=4)

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

    with sqlite3.connect(Path(path) / "data.db") as connection:
        connection.execute(
            "INSERT INTO ack_queue_default (data, timestamp, status) VALUES (?, ?, ?)",
            (base64.b64encode(pickle.dumps({"format": "base64"}, protocol=4)), 0, 0),
        )

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
        uncompressed = queue.get(block=False)
        assert uncompressed == {"format": "base64"}
        queue.ack(uncompressed)
        new = queue.get(block=False)
        assert new == {"format": "new"}
        queue.ack_failed(new)
        assert queue.acked_count() == 2
        assert queue.ack_failed_count() == 1
        with sqlite3.connect(Path(path) / "data.db") as connection:
            rows = connection.execute("SELECT data FROM ack_queue_default ORDER BY _id").fetchall()
        assert [persistent_queue.Base64QueueSerializer.loads(row[0]) for row in rows] == [
            {"format": "updated"}, {"format": "base64"}, {"format": "new"},
        ]
        assert base64.b64decode(rows[0][0]).startswith(persistent_queue.QUEUE_COMPRESSION_MARKER)
        assert base64.b64decode(rows[2][0]).startswith(persistent_queue.QUEUE_COMPRESSION_MARKER)
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


@pytest.mark.parametrize("keep_latest", [0, 200])
def test_cleanup_entire_success_backlog_preserves_other_statuses(tmp_path, monkeypatch, keep_latest):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    monkeypatch.setattr(persistent_queue, "QUEUE_VACUUM_MIN_FREE_BYTES", 0)
    queue = SQLiteAckQueue(path=str(tmp_path / "queue"), auto_commit=True)
    try:
        success_ids = [queue.put(f"success-{idx}" + "x" * 1000) for idx in range(1205)]
        # Acknowledge in reverse order to verify retention follows queue insertion order.
        for item_id in reversed(success_ids):
            queue.ack(id=item_id)
        failed_id = queue.put("failed")
        queue.ack_failed(id=failed_id)
        processing_id = queue.put("processing")
        queue.get(block=False, id=processing_id)
        ready_id = queue.put("ready")
        before_pages = queue._conn.execute("PRAGMA page_count").fetchone()[0]

        persistent_queue._shrink_persistent_queue(queue, "queue", keep_latest=keep_latest)

        assert queue.acked_count() == keep_latest
        assert queue.ack_failed_count() == 1
        assert queue.unack_count() == 1
        assert queue._count() == 1
        remaining_ids = [item["id"] for item in queue.queue()]
        expected_success = success_ids[-keep_latest:] if keep_latest else []
        assert remaining_ids == expected_success + [failed_id, processing_id, ready_id]
        assert queue.get(block=False) == "ready"
        assert queue._conn.execute("PRAGMA page_count").fetchone()[0] < before_pages
    finally:
        queue.close()


@pytest.mark.parametrize("acked_count", [0, 199, 200])
def test_cleanup_skips_vacuum_within_retention(monkeypatch, acked_count):
    queue = FakeQueue([])
    queue._putter.execute.return_value.fetchone.return_value = (0, 100, 4096)
    monkeypatch.setattr(queue, "acked_count", lambda: acked_count)
    persistent_queue._shrink_persistent_queue(queue, "queue")
    assert queue.clear_calls == []
    assert queue.shrink_calls == 0


def test_startup_cleans_all_queues_and_closes_connections(monkeypatch, tmp_path):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queues = {}
    for name in ("ingest_queue", "doc_type_queue", "scan_finding_queue"):
        queue = SQLiteAckQueue(path=str(tmp_path / name), auto_commit=True)
        for idx in range(1205):
            queue.ack(id=queue.put(idx))
        queue.put("pending")
        queue.close()

    def get_queue(db, name):
        assert db == "db"
        queue = SQLiteAckQueue(path=str(tmp_path / name), auto_commit=True)
        queues[name] = queue
        return queue

    monkeypatch.setattr(persistent_queue, "get_persistent_queue", get_queue)
    monkeypatch.setattr(SQLiteAckQueue, "shrink_disk_usage", lambda self: pytest.fail("Startup must not vacuum"))
    persistent_queue.cleanup_persistent_queues_on_startup("db")
    assert len(queues) == 3
    for name, queue in queues.items():
        with pytest.raises(sqlite3.ProgrammingError):
            queue.acked_count()
        reopened = SQLiteAckQueue(path=str(tmp_path / name), auto_commit=True)
        assert reopened.acked_count() == 0
        assert reopened.get(block=False) == "pending"
        reopened.close()


def test_idle_cleanup_repeats_without_consuming_new_items(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(persistent_queue.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(persistent_queue.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue = FakeQueue([])
    calls = [0]

    def get(block, timeout):
        calls[0] += 1
        if calls[0] <= 2:
            clock[0] += 601
            raise Empty
        return "first"

    monkeypatch.setattr(queue, "get", get)
    assert next(persistent_queue.persistent_queue_get(queue)) == "first"
    assert queue.clear_calls == [(1500, 200), (1500, 200)]
    assert queue.shrink_calls == 2


@pytest.mark.parametrize("fail_operation", ["acked_count", "clear_acked_data", "shrink_disk_usage", "execute"])
def test_maintenance_failure_warns_and_retries(monkeypatch, caplog, fail_operation):
    clock = [0.0]
    monkeypatch.setattr(persistent_queue.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue = FakeQueue([])
    maintenance = persistent_queue.QueueMaintenance(queue)
    target = queue._putter if fail_operation == "execute" else queue
    original = getattr(target, fail_operation)

    def fail(*args, **kwargs):
        raise RuntimeError("database locked")

    monkeypatch.setattr(target, fail_operation, fail)
    clock[0] = 600
    maintenance.check()
    assert "database locked" in caplog.text
    assert caplog.records[-1].levelname == "WARNING"
    monkeypatch.setattr(target, fail_operation, original)
    clock[0] = 1200
    maintenance.check()
    assert queue.shrink_calls == 1


def test_default_maintenance_waits_ten_minutes(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(persistent_queue.time, "monotonic", lambda: clock[0])
    cleanup = MagicMock()
    monkeypatch.setattr(persistent_queue, "_shrink_persistent_queue", cleanup)
    maintenance = persistent_queue.QueueMaintenance(FakeQueue([]))
    for elapsed in (60, 599):
        clock[0] = elapsed
        maintenance.check()
        cleanup.assert_not_called()
    clock[0] = 600
    maintenance.check()
    cleanup.assert_called_once()


@pytest.mark.parametrize("free_pages,total_pages,page_size,expected", [
    (16383, 65532, 4096, False),  # Ratio met, bytes below threshold.
    (16384, 65537, 4096, False),  # Bytes met, ratio below threshold.
    (16384, 65536, 4096, True),  # Both thresholds exactly met.
    (20000, 70000, 4096, True),
    (8192, 32768, 8192, True),  # Honor the database's actual page size.
    (262143, 13631488, 4096, False),  # One page below 1 GiB, ratio below threshold.
    (262144, 13631488, 4096, False),  # Exactly 1 GiB does not override the ratio.
    (262145, 13631488, 4096, True),  # One page above 1 GiB overrides the ratio.
    (524288, 13631488, 4096, True),  # 2 GiB free in a 52 GiB database.
    (131072, 6815744, 8192, False),  # Exactly 1 GiB with 8 KiB pages.
    (131073, 6815744, 8192, True),  # Maximum threshold honors the actual page size.
    (0, 0, 4096, False),
])
def test_runtime_vacuum_thresholds_without_new_deletions(
        monkeypatch, caplog, free_pages, total_pages, page_size, expected):
    queue = FakeQueue([])
    monkeypatch.setattr(queue, "acked_count", lambda: 200)
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue._putter.execute.return_value.fetchone.return_value = (free_pages, total_pages, page_size)

    def shrink():
        assert not queue.tran_lock.locked()
        queue.shrink_calls += 1

    def execute(sql):
        assert queue.tran_lock.locked()
        assert "pragma_freelist_count()" in sql
        return queue._putter.execute.return_value

    monkeypatch.setattr(queue, "shrink_disk_usage", shrink)
    queue._putter.execute.side_effect = execute
    with caplog.at_level("INFO"):
        persistent_queue._shrink_persistent_queue(queue, "queue")
    assert queue.clear_calls == []
    assert queue.shrink_calls == int(expected)
    queue._putter.execute.return_value.close.assert_called_once()
    if expected:
        assert "reclaimable bytes" in caplog.text
        assert "free pages" in caplog.text
        assert "Vacuumed queue in" in caplog.text


@pytest.mark.parametrize("threshold", ["QUEUE_VACUUM_MIN_FREE_BYTES", "QUEUE_VACUUM_MAX_FREE_BYTES"])
def test_real_queue_defers_vacuum_until_runtime_threshold(monkeypatch, tmp_path, threshold):
    monkeypatch.setattr(persistent_queue, "log_heap_stats", lambda: None)
    monkeypatch.setattr(persistent_queue, "log_gpu_memory_summary", lambda: None)
    queue = SQLiteAckQueue(path=str(tmp_path / "queue"), auto_commit=True)
    try:
        for idx in range(250):
            queue.ack(id=queue.put(f"{idx}" + "x" * 4096))
        failed_id = queue.put("failed")
        queue.ack_failed(id=failed_id)
        processing_id = queue.put("processing")
        queue.get(block=False, id=processing_id)
        queue.put("pending")
        before_pages = queue._putter.execute("PRAGMA page_count").fetchone()[0]
        persistent_queue._shrink_persistent_queue(queue, "queue", keep_latest=0, vacuum=False)
        assert queue.acked_count() == 0
        assert queue._putter.execute("PRAGMA page_count").fetchone()[0] == before_pages

        # Default thresholds defer compaction for this small database, even after deletion.
        persistent_queue._shrink_persistent_queue(queue, "queue")
        assert queue._putter.execute("PRAGMA page_count").fetchone()[0] == before_pages
        monkeypatch.setattr(persistent_queue, threshold, 4096)
        persistent_queue._shrink_persistent_queue(queue, "queue")
        assert queue._putter.execute("PRAGMA page_count").fetchone()[0] < before_pages
        assert queue.ack_failed_count() == 1
        assert queue.unack_count() == 1
        assert queue.get(block=False) == "pending"
    finally:
        queue.close()


def test_shutdown_does_not_claim_pending_persistent_items(tmp_path):
    queue = SQLiteAckQueue(str(tmp_path), auto_commit=True)
    try:
        queue.put("pending")
        stop = Event()
        stop.set()
        assert list(persistent_queue.persistent_queue_get(queue, stop_event=stop)) == []
        assert queue.get(block=False) == "pending"
    finally:
        queue.close()


def test_shutdown_race_returns_claimed_item_to_persistent_queue(tmp_path):
    queue = SQLiteAckQueue(str(tmp_path), auto_commit=True)
    stop = Event()
    original_get = queue.get

    def get(**kwargs):
        item = original_get(**kwargs)
        stop.set()
        return item

    try:
        queue.put("pending")
        queue.get = get
        assert list(persistent_queue.persistent_queue_get(queue, stop_event=stop)) == []
        assert queue.unack_count() == 0
        assert original_get(block=False) == "pending"
    finally:
        queue.close()


def test_shutdown_interrupts_empty_queue_poll_without_sleep(monkeypatch):
    stop = Event()

    def get(**kwargs):
        assert kwargs["timeout"] == 1
        stop.set()
        raise Empty

    queue = Mock(path="queue", get=get)
    sleep = Mock()
    monkeypatch.setattr(persistent_queue.time, "sleep", sleep)
    assert list(persistent_queue.persistent_queue_get(queue, stop_event=stop)) == []
    sleep.assert_not_called()


@pytest.mark.parametrize("existing_columns", [None, "status", "status, _id"])
def test_index_migration_preserves_existing_records_and_is_idempotent(tmp_path, existing_columns):
    legacy = SQLiteAckQueue(str(tmp_path), auto_commit=True)
    ids = [legacy.put(f"item-{status}") for status in (0, 1, 2, 5, 9)]
    for item_id, status in zip(ids, (0, 1, 2, 5, 9), strict=True):
        legacy._conn.execute("UPDATE ack_queue_default SET status = ? WHERE _id = ?", (status, item_id))
    legacy._conn.commit()
    before = legacy._conn.execute("SELECT * FROM ack_queue_default ORDER BY _id").fetchall()
    if existing_columns is not None:
        legacy._conn.execute(f"CREATE INDEX ack_queue_status_id ON ack_queue_default ({existing_columns})")
    before_schema = legacy._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'ack_queue_status_id'"
    ).fetchone()
    legacy.close()

    for _ in range(2):
        queue = persistent_queue.open_persistent_queue(str(tmp_path), auto_resume=False)
        try:
            assert queue._conn.execute("SELECT * FROM ack_queue_default ORDER BY _id").fetchall() == before
            columns = queue._conn.execute("PRAGMA index_info(ack_queue_status_id)").fetchall()
            expected_columns = ["status", "_id"] if existing_columns == "status, _id" else ["status"]
            assert [column[2] for column in columns] == expected_columns
            assert len(queue._conn.execute("PRAGMA index_list(ack_queue_default)").fetchall()) == 1
            if before_schema is not None:
                assert queue._conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'ack_queue_status_id'"
                ).fetchone() == before_schema
            plan = queue._conn.execute(
                "EXPLAIN QUERY PLAN SELECT COUNT(_id) FROM ack_queue_default WHERE status <= 2"
            ).fetchall()
            assert "COVERING INDEX ack_queue_status_id" in str(plan)
            assert persistent_queue.read_active_queue_size(tmp_path) == 3
            assert queue.unack_count() == 1
        finally:
            queue.close()


def test_index_migration_closes_queue_and_propagates_failure(monkeypatch):
    queue = Mock(tran_lock=threading.Lock(), _putter=MagicMock())
    queue._putter.__enter__.return_value.execute.side_effect = sqlite3.OperationalError("disk full")
    monkeypatch.setattr(persistent_queue.persistqueue, "SQLiteAckQueue", lambda **kwargs: queue)
    with pytest.raises(sqlite3.OperationalError, match="disk full"):
        persistent_queue.open_persistent_queue("queue")
    queue.close.assert_called_once()


def test_read_only_count_does_not_create_missing_database(tmp_path):
    with pytest.raises(sqlite3.OperationalError):
        persistent_queue.read_active_queue_size(tmp_path)
    assert not (tmp_path / "data.db").exists()


@pytest.mark.asyncio
async def test_statistics_use_thread_owned_connections_without_resuming(tmp_path, monkeypatch):
    for name in ("ingest_queue", "doc_type_queue"):
        queue = persistent_queue.open_persistent_queue(str(tmp_path / name))
        queue.put("ready")
        queue.put("processing")
        queue.get(block=False)
        queue.close()
    monkeypatch.setattr(persistent_queue, "persistent_queue_path", lambda db, name: tmp_path / name)
    original_read = persistent_queue.read_active_queue_size
    loop_thread = threading.get_ident()

    def read(path):
        assert threading.get_ident() != loop_thread
        return original_read(path)

    monkeypatch.setattr(persistent_queue, "read_active_queue_size", read)
    assert await persistent_queue.persistent_queue_sizes("db") == (2, 2)
    for name in ("ingest_queue", "doc_type_queue"):
        queue = persistent_queue.open_persistent_queue(str(tmp_path / name), auto_resume=False)
        assert queue.unack_count() == 1
        queue.close()


@pytest.mark.asyncio
async def test_statistics_do_not_block_event_loop(monkeypatch):
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = Event()

    def read(path):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5)
        return 4

    monkeypatch.setattr(persistent_queue, "read_active_queue_size", read)
    task = asyncio.create_task(persistent_queue.persistent_queue_sizes("db"))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert not task.done()
    finally:
        release.set()
    assert await task == (4, 4)


@pytest.mark.asyncio
async def test_writer_commits_concurrent_items_and_preserves_processing(tmp_path):
    queue = persistent_queue.open_persistent_queue(str(tmp_path))
    queue.put("processing")
    queue.get(block=False)
    queue.close()
    writer = persistent_queue.AsyncIngestWriter(str(tmp_path))
    try:
        ids = await asyncio.gather(*(writer.put(f"item-{idx}") for idx in range(20)))
        assert ids == sorted(ids)
        reopened = persistent_queue.open_persistent_queue(str(tmp_path), auto_resume=False)
        try:
            assert reopened.unack_count() == 1
            assert reopened._count() == 20
            for idx in range(20):
                item = reopened.get(block=False)
                assert item == f"item-{idx}"
                reopened.ack(item)
        finally:
            reopened.close()
    finally:
        await asyncio.to_thread(writer.close)
    writer.close()
    with pytest.raises(RuntimeError, match="closed"):
        await writer.put("rejected")


@pytest.mark.asyncio
async def test_writer_cancellation_drains_write_before_releasing_slot(monkeypatch):
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = Event()
    calls = []
    loop_thread = threading.get_ident()

    class Queue:
        def put(self, item):
            assert threading.get_ident() != loop_thread
            calls.append(item)
            if item == "first":
                loop.call_soon_threadsafe(entered.set)
                assert release.wait(5)
            return len(calls)

        def close(self):
            assert threading.get_ident() != loop_thread

    monkeypatch.setattr(persistent_queue, "open_persistent_queue", lambda *args, **kwargs: Queue())
    writer = persistent_queue.AsyncIngestWriter("unused")
    first = asyncio.create_task(writer.put("first"))
    second = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        first.cancel()
        await asyncio.sleep(0)
        first.cancel()
        second = asyncio.create_task(writer.put("second"))
        await asyncio.sleep(0)
        assert calls == ["first"]
        assert not first.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert await second == 2
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)
        await asyncio.to_thread(writer.close)


@pytest.mark.asyncio
async def test_writer_recovers_from_open_and_write_errors(monkeypatch):
    queue = Mock()
    queue.put.side_effect = [sqlite3.OperationalError("database locked"), 1]
    open_queue = Mock(side_effect=[sqlite3.OperationalError("disk full"), queue])
    monkeypatch.setattr(persistent_queue, "open_persistent_queue", open_queue)
    writer = persistent_queue.AsyncIngestWriter("unused")
    try:
        with pytest.raises(sqlite3.OperationalError, match="disk full"):
            await writer.put("first")
        with pytest.raises(sqlite3.OperationalError, match="database locked"):
            await writer.put("second")
        assert await writer.put("third") == 1
        open_queue.assert_called_with("unused", auto_resume=False)
    finally:
        await asyncio.to_thread(writer.close)
    queue.close.assert_called_once()


def test_unused_writer_closes_without_opening_queue(monkeypatch):
    open_queue = Mock()
    monkeypatch.setattr(persistent_queue, "open_persistent_queue", open_queue)
    writer = persistent_queue.AsyncIngestWriter("unused")
    writer.close()
    writer.close()
    open_queue.assert_not_called()


@pytest.mark.asyncio
async def test_writer_shutdown_drains_inflight_write_and_rejects_waiters(monkeypatch):
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = Event()
    closed = Event()

    class Queue:
        def put(self, item):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(5)
            return 1

        def close(self):
            closed.set()

    monkeypatch.setattr(persistent_queue, "open_persistent_queue", lambda *args, **kwargs: Queue())
    writer = persistent_queue.AsyncIngestWriter("unused")
    writing = asyncio.create_task(writer.put("first"))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        shutdown = loop.run_in_executor(None, writer.close)
        # Synchronize with shutdown without relying on scheduler timing.
        await asyncio.to_thread(wait_for_writer_close, writer)
        assert not closed.is_set()
        with pytest.raises(RuntimeError, match="closed"):
            # Directly exercise a waiter after the first write finishes below.
            release.set()
            await writer.put("second")
        assert await writing == 1
        await shutdown
        assert closed.is_set()
    finally:
        release.set()
        await asyncio.gather(writing, return_exceptions=True)
        await asyncio.to_thread(writer.close)


def wait_for_writer_close(writer):
    import time

    deadline = time.monotonic() + 2
    while not writer.closed and time.monotonic() < deadline:
        time.sleep(0.001)
    assert writer.closed
