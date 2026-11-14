"""Durable failure evidence and read-only inspection."""

import sqlite3
from contextlib import closing

from shyhurricane.persistent_queue import open_persistent_queue
from shyhurricane.queue_failures import inspect_failures


def test_failure_history(tmp_path):
    path = tmp_path / "queues" / "doc_type_queue"
    queue = open_persistent_queue(str(path))
    queue.put("payload")
    item = queue.get()
    try:
        raise ValueError("broken")
    except ValueError:
        queue.ack_failed(item)
    row = inspect_failures(tmp_path)[0]
    assert row["error_type"] == "ValueError"
    assert "broken" in row["detail"]
    queue.ack_failed(id=row["id"])
    assert inspect_failures(tmp_path)[0]["attempts"] == 2
    queue.ack(id=row["id"])
    assert inspect_failures(tmp_path) == []
    assert len(inspect_failures(tmp_path, resolved=True)) == 1
    queue.close()


def test_legacy_and_missing(tmp_path):
    assert inspect_failures(tmp_path) == []
    path = tmp_path / "queues" / "doc_type_queue"
    path.mkdir(parents=True)
    with closing(sqlite3.connect(path / "data.db")) as connection:
        connection.execute("CREATE TABLE ack_queue_default (_id INTEGER,status INTEGER)")
        connection.execute("INSERT INTO ack_queue_default VALUES (1,9)")
        connection.commit()
    assert inspect_failures(tmp_path)[0]["detail"] == "Details unavailable"
    assert inspect_failures(tmp_path, queue="graph") == []


def test_bounded_error_and_cleanup(tmp_path):
    queue = open_persistent_queue(str(tmp_path / "queues" / "graph_queue"))
    assert queue.ack_failed(id=999) is None
    queue.put("payload")
    item = queue.get()
    queue.ack_failed(item, error=RuntimeError("x" * 70000), stage="references")
    row = inspect_failures(tmp_path, limit=1)[0]
    assert row["detail"].endswith("[truncated]")
    assert len(row["detail"].encode()) <= 65536
    with queue.tran_lock, queue._putter as connection:
        connection.execute("DELETE FROM ack_queue_default")
        assert connection.execute("SELECT count(*) FROM queue_failure").fetchone()[0] == 0
    queue.close()


def test_cli(tmp_path, monkeypatch, capsys):
    import sys

    import pytest

    from shyhurricane.queue_failures import main

    monkeypatch.setattr(sys, "argv", ["queue_failures", str(tmp_path)])
    main()
    assert capsys.readouterr().out.strip() == "[]"
    monkeypatch.setattr(sys, "argv", ["queue_failures", str(tmp_path), "--limit", "0"])
    with pytest.raises(SystemExit):
        main()


def test_relationship_warnings():
    import logging

    from shyhurricane.logging_config import Neo4jPropertyWarningFilter

    warning_filter = Neo4jPropertyWarningFilter()
    message = "gql_status='01N51' The relationship type `DEPENDS_ON` does not exist in database query: huge"
    record = logging.LogRecord("neo4j.notifications", logging.WARNING, "", 1, message, (), None)
    assert warning_filter.filter(record)
    assert "huge" not in record.getMessage()
    duplicate = logging.LogRecord("neo4j.notifications", logging.WARNING, "", 1, message, (), None)
    assert not warning_filter.filter(duplicate)


def test_cli_detail_and_summary(tmp_path, monkeypatch, capsys):
    import json
    import sys

    from shyhurricane.queue_failures import main

    queue = open_persistent_queue(str(tmp_path / "queues" / "graph_queue"))
    try:
        queue.put("payload")
        queue.ack_failed(queue.get(), error=ValueError("first line\nlast line"))
        for options, expected in [
            ([], "last line"),
            (["--detail"], "ValueError: first line\nlast line\n"),
        ]:
            monkeypatch.setattr(sys, "argv", ["queue_failures", str(tmp_path), "--queue", "graph", *options])
            main()
            rows = json.loads(capsys.readouterr().out)
            assert len(rows) == 1
            assert rows[0]["detail"].endswith(expected)
    finally:
        queue.close()


def test_cli_rejects_excessive_limit(tmp_path, monkeypatch, capsys):
    import sys

    import pytest

    from shyhurricane.queue_failures import main

    monkeypatch.setattr(sys, "argv", ["queue_failures", str(tmp_path), "--limit", "1001"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert "limit must be between" in capsys.readouterr().err
