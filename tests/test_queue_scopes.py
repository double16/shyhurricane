"""Scope metadata survives queue updates, handoffs, cleanup and restart."""

import json
import sqlite3

import persistqueue
import pytest
from haystack import Document

from shyhurricane.persistent_queue import Base64QueueSerializer, open_persistent_queue
from shyhurricane.queue_scopes import item_scopes, scoped_queue_rows


def capture(url="https://example.com/app", **extra):
    return {
        "timestamp": "2026-10-15T12:00:00Z",
        "request": {"endpoint": url, "method": "GET"},
        "response": {"status_code": 200, "body": "body"},
        **extra,
    }


@pytest.mark.parametrize(
    "item,expected",
    [
        (None, [("", "", "", 0)]),
        (capture(), [("https://example.com/app", "", "", 0)]),
        (json.dumps(capture()).encode(), [("https://example.com/app", "", "", 0)]),
        (json.dumps(capture(), indent=2), [("https://example.com/app", "", "", 0)]),
        (
            "\n".join(map(json.dumps, [capture(), capture("https://other.test/")])),
            [("https://example.com/app", "", "", 0), ("https://other.test/", "", "", 0)],
        ),
        ({"data": {"url": "https://example.com/"}, "id": "capture"}, [("https://example.com/", "", "capture", 0)]),
        ({"id": "capture", "reanalysis_ticket": "ticket"}, [("", "", "capture", 0)]),
        (
            {"log": {"entries": [{"request": {"url": "https://example.com/"}}, {"request": {}}]}},
            [("https://example.com/", "", "", 0)],
        ),
        ({"log": {}}, [("", "", "", 1)]),
        ({}, [("", "", "", 1)]),
        (42, [("", "", "", 1)]),
        ("invalid", [("", "", "", 1)]),
        (Document(id="doc", meta={"url": "https://example.com/"}), [("https://example.com/", "doc", "", 0)]),
        (Document(id="doc"), [("", "doc", "", 1)]),
        (
            "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\n\r\nhello",
            [("http://example.com/hello", "", "", 0)],
        ),
    ],
)
def test_item_scopes(item, expected):
    assert item_scopes(item) == expected


def test_scopes_transaction_update_restart_and_cleanup(tmp_path):
    queue = open_persistent_queue(str(tmp_path))
    row_id = queue.put(json.dumps(capture()))
    assert scoped_queue_rows(tmp_path, 1) == [(row_id, 0, "https://example.com/app", "", "", 0)]
    queue.update(json.dumps(capture("https://other.test/")), id=row_id)
    queue.get()
    assert scoped_queue_rows(tmp_path, 1)[0][1:3] == (2, "https://other.test/")
    queue.close()
    queue = open_persistent_queue(str(tmp_path), auto_resume=False)
    assert scoped_queue_rows(tmp_path, 1)[0][1] == 2
    queue.ack(id=row_id)
    assert scoped_queue_rows(tmp_path, 1) == []
    queue.clear_acked_data(max_delete=0, keep_latest=0)
    assert queue._putter.execute("SELECT COUNT(*) FROM indexing_scope").fetchone()[0] == 0
    queue.close()


def test_backfills_legacy_rows_and_preserves_unreadable_payload(tmp_path):
    legacy = persistqueue.SQLiteAckQueue(str(tmp_path), serializer=Base64QueueSerializer)
    row_id = legacy.put(json.dumps(capture()))
    broken_id = legacy.put("broken")
    with legacy._putter as connection:
        connection.execute("UPDATE ack_queue_default SET data=? WHERE _id=?", (b"broken!", broken_id))
    legacy.close()
    queue = open_persistent_queue(str(tmp_path), auto_resume=False)
    rows = scoped_queue_rows(tmp_path, 1)
    assert rows == [(row_id, 0, "https://example.com/app", "", "", 0), (broken_id, 0, "", "", "", 1)]
    queue.close()


def test_failed_metadata_write_rolls_back_payload_insert_and_update(tmp_path, monkeypatch):
    queue = open_persistent_queue(str(tmp_path))
    row_id = queue.put(json.dumps(capture()))

    def fail(*args):
        raise sqlite3.OperationalError("metadata unavailable")

    monkeypatch.setattr(queue, "_write_scopes", fail)
    with pytest.raises(sqlite3.OperationalError):
        queue.put(json.dumps(capture("https://other.test/")))
    with pytest.raises(sqlite3.OperationalError):
        queue.update("new payload", id=row_id)
    assert queue.get() == json.dumps(capture())
    assert len(scoped_queue_rows(tmp_path, 1)) == 1
    queue.close()


def test_missing_database_is_empty_and_unmigrated_database_is_unavailable(tmp_path):
    assert scoped_queue_rows(tmp_path, 1) == []
    queue = persistqueue.SQLiteAckQueue(str(tmp_path))
    with pytest.raises(sqlite3.OperationalError, match="indexing_scope"):
        scoped_queue_rows(tmp_path, 1)
    queue.close()
