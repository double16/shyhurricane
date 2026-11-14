"""Wall-clock measurements retain no SQL statements or captured values."""

import json
import sqlite3

import pytest

from shyhurricane.graph.batch_timing import Connection, account
from shyhurricane.graph.parser_diagnostics import report_batch


def test_sql_accounting_and_scope():
    connection = sqlite3.connect(":memory:", factory=Connection)
    connection.execute("CREATE TABLE example(value)")
    connection.executemany("INSERT INTO example VALUES (?)", [])
    with account() as stats:
        connection.executemany("INSERT INTO example VALUES (?)", [(1,), (2,)])
        assert connection.execute("SELECT value FROM example").fetchone() == (1,)
        assert connection.execute("SELECT value FROM example").fetchall() == [(1,), (2,)]
        assert list(connection.execute("SELECT value FROM example")) == [(1,), (2,)]
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("SELECT missing FROM example")
    assert stats["sql_calls"] >= 9
    assert stats["sql_seconds"] >= 0
    saved = dict(stats)
    connection.execute("SELECT 1").fetchone()
    assert stats == saved
    with account() as outer:
        with account() as inner:
            connection.execute("SELECT 1").fetchone()
        assert outer["sql_calls"] == 0
        assert inner["sql_calls"] == 2
    connection.close()


def test_report_channel(tmp_path, monkeypatch):
    monkeypatch.delenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", raising=False)
    report_batch({"rows": 1})
    path = tmp_path / "diagnostics"
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(path))
    report_batch({"rows": 2, "sql_seconds": 0.1})
    row = json.loads(path.read_text())
    assert row["stage"] == "archive-batch"
    assert row["rows"] == 2
    assert row["sql_seconds"] == 0.1
    assert row["timestamp"] > 0
