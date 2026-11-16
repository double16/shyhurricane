"""Bounded recovery of receiptless dependency failures."""

import sqlite3

import pytest

from shyhurricane.graph.dependency_recovery import recover_dependents


@pytest.fixture
def connection():
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(
            "CREATE TABLE work(id TEXT PRIMARY KEY,status TEXT,error TEXT);"
            "CREATE INDEX graph_work_status_id ON work(status,id);"
            "CREATE TABLE analysis_policies(capture_id TEXT PRIMARY KEY,mode TEXT);"
            "CREATE TABLE graph_epoch_inputs(token TEXT PRIMARY KEY,capture_id TEXT,mode TEXT,"
            "epoch_id INTEGER,state TEXT,request_token TEXT);"
        )
        yield connection


@pytest.mark.parametrize("dependency_status,expected", [("complete", 1), ("failed", 0), (None, 0)])
@pytest.mark.parametrize("policy", [None, "full"])
def test_only_recovered_dependencies_schedule_once(connection, dependency_status, expected, policy):
    dependency = "a" * 64
    connection.execute("INSERT INTO work VALUES ('consumer','failed',?)", (f"Dependency {dependency} failed",))
    if dependency_status:
        connection.execute("INSERT INTO work VALUES (?,?, '')", (dependency, dependency_status))
    if policy:
        connection.execute("INSERT INTO analysis_policies VALUES ('consumer',?)", (policy,))
    assert recover_dependents(connection) == ("", expected)
    assert recover_dependents(connection) == ("", 0)
    assert connection.execute("SELECT status FROM work WHERE id='consumer'").fetchone() == ("failed",)
    if expected:
        assert connection.execute("SELECT mode FROM graph_epoch_inputs").fetchone()[0] == (policy or "summary")


@pytest.mark.parametrize("error", [None, "invalid syntax", "Dependency missing failed"])
def test_terminal_or_malformed_errors_are_not_retried(connection, error):
    connection.execute("INSERT INTO work VALUES ('consumer','failed',?)", (error,))
    assert recover_dependents(connection) == ("", 0)


def test_bounded_pages_skip_active_work_and_wrap(connection):
    dependency = "a" * 64
    connection.execute("INSERT INTO work VALUES (?,'complete','')", (dependency,))
    for capture in ["consumer1", "consumer2"]:
        connection.execute("INSERT INTO work VALUES (?,'failed',?)", (capture, f"Dependency {dependency} failed"))
    connection.execute("INSERT INTO graph_epoch_inputs VALUES ('existing','consumer1','summary',1,'active',NULL)")
    assert recover_dependents(connection, limit=1) == ("consumer1", 0)
    assert recover_dependents(connection, after="consumer1", limit=1) == ("consumer2", 1)
    assert recover_dependents(connection, after="consumer2", limit=1) == ("", 0)


def test_failed_page_uses_status_index_with_unrelated_work(connection):
    connection.executemany(
        "INSERT INTO work VALUES (?,'complete','')", ((f"unrelated-{i}",) for i in range(1000)),
    )
    plan = connection.execute(
        "EXPLAIN QUERY PLAN SELECT id,error FROM work "
        "WHERE status='failed' AND id>? ORDER BY id LIMIT ?", ("", 100),
    ).fetchall()
    assert any("graph_work_status_id" in row[3] for row in plan)
    assert recover_dependents(connection) == ("", 0)
