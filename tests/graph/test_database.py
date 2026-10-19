from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import database
from shyhurricane.graph.database import GraphStore, resolve_uri
from shyhurricane.graph.extract import extract


@pytest.fixture(autouse=True)
def memory_settings(monkeypatch):
    for name in ("NEO4J_HEAP_SIZE", "NEO4J_PAGECACHE_SIZE", "NEO4J_TRANSACTION_MEMORY_LIMIT"):
        monkeypatch.delenv(name, raising=False)


def test_memory_defaults_overrides_and_container_reuse_warning(monkeypatch, tmp_path, caplog):
    assert database.memory_environment() == [
        "NEO4J_server_memory_heap_initial__size=1g",
        "NEO4J_server_memory_heap_max__size=1g",
        "NEO4J_server_memory_pagecache_size=1g",
    ]
    monkeypatch.setenv("NEO4J_HEAP_SIZE", "2G")
    monkeypatch.setenv("NEO4J_PAGECACHE_SIZE", "512m")
    monkeypatch.setenv("NEO4J_TRANSACTION_MEMORY_LIMIT", "1g")
    environment = database.memory_environment()
    assert "NEO4J_server_memory_heap_max__size=2G" in environment
    assert "NEO4J_dbms_memory_transaction_total_max=1g" in environment
    info = {
        "Mounts": [{"Source": str(tmp_path), "Destination": "/data"}],
        "State": {"Running": True},
        "Config": {"Env": environment},
    }
    monkeypatch.setattr(database, "_inspect_container", lambda name: info)
    monkeypatch.setattr(database, "_get_published_port", lambda *args: ("127.0.0.1", 17687))
    command = MagicMock()
    monkeypatch.setattr(database, "_run", command)
    assert resolve_uri(str(tmp_path)) == "bolt://127.0.0.1:17687"
    assert "different memory settings" not in caplog.text
    info["Config"]["Env"] = ["NEO4J_server_memory_heap_max__size=512m"]
    resolve_uri(str(tmp_path))
    assert "different memory settings" in caplog.text
    command.assert_not_called()


@pytest.mark.parametrize(
    "name,value",
    [
        ("NEO4J_HEAP_SIZE", ""),
        ("NEO4J_HEAP_SIZE", "-1g"),
        ("NEO4J_PAGECACHE_SIZE", "0m"),
        ("NEO4J_TRANSACTION_MEMORY_LIMIT", "2g"),
        ("NEO4J_HEAP_SIZE", "1g;echo bad"),
    ],
)
def test_invalid_memory_configuration(name, value, monkeypatch):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        database.memory_environment()


def test_managed_container_create_reuse_start_and_validate(monkeypatch, tmp_path):
    storage = tmp_path / "graph"
    info = {"Mounts": [{"Source": str(storage), "Destination": "/data"}], "State": {"Running": True}}
    commands = []
    inspections = iter([None, info, info, {**info, "State": {"Running": False}}, info, None, None])
    monkeypatch.setattr(database, "_inspect_container", lambda name: next(inspections))
    monkeypatch.setattr(database, "_find_available_port", lambda host: 12345)
    monkeypatch.setattr(database, "_get_published_port", lambda info, port: ("127.0.0.1", 12345))
    monkeypatch.setattr(database, "_run", lambda command: commands.append(command))
    for _ in range(3):
        assert resolve_uri(str(storage)) == "bolt://127.0.0.1:12345"
    assert any(command[1] == "start" for command in commands)
    assert "/data:rw" in " ".join(commands[0])
    assert "NEO4J_server_memory_heap_initial__size=1g" in commands[0]
    with pytest.raises(RuntimeError, match="inspect"):
        resolve_uri(str(storage))
    monkeypatch.setattr(database, "_inspect_container", lambda name: {"State": {"Running": True}})
    with pytest.raises(RuntimeError, match="mount"):
        resolve_uri(str(storage))


@pytest.mark.parametrize("location", ["https://example.com", "bolt://user:secret@example.com", "bolt://"])
def test_invalid_locations(location):
    with pytest.raises(ValueError):
        resolve_uri(location)


def test_driver_read_schema_and_publication_handoff(monkeypatch, event):
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value
    transaction = MagicMock()
    transaction.run.return_value = [{"value": 1}]
    session.execute_read.side_effect = lambda action: action(transaction)
    session.execute_write.side_effect = lambda action: action(transaction)
    monkeypatch.setattr(database.GraphDatabase, "driver", lambda *args, **kwargs: driver)
    monkeypatch.setenv("NEO4J_PASSWORD", "password")
    store = GraphStore("bolt://localhost:7687")
    cleanup = MagicMock()
    monkeypatch.setattr(store, "cleanup", cleanup)
    assert store.ready()
    assert any("CREATE INDEX graph_publication_capture" in str(call.args[0]) for call in session.run.call_args_list)
    assert all(call.args[0].timeout == 120 for call in session.run.call_args_list[:-1])
    assert str(session.run.call_args.args[0]) == "RETURN 1"
    assert session.run.call_args.args[0].timeout == 15
    cleanup.assert_not_called()
    schema_calls = session.run.call_count
    assert store.ready()
    assert session.run.call_count == schema_calls + 1
    assert store.read("RETURN 1 AS value") == [{"value": 1}]
    publisher = MagicMock()
    monkeypatch.setattr("shyhurricane.graph.publication.GraphPublisher", lambda store: publisher)
    graph = extract(event(body='<a href="/next">next</a>'))
    store.publish(graph)
    publisher.publish.assert_called_once_with(graph)
    monkeypatch.setattr(
        store,
        "read",
        lambda *args, **kwargs: [
            {"resource_key": "GET /", "observed_at": 1, "entity_estimate": 1, "relationship_estimate": 2}
        ],
    )
    assert store.statistics()["entities"] == 1
    store.close()
    store.close()
    driver.close.assert_called_once()
    monkeypatch.setattr(
        "shyhurricane.server_config.get_server_config", lambda: SimpleNamespace(graph_database="custom")
    )
    assert database.graph_location() == "custom"


@pytest.mark.parametrize("timeout,expected", [(0.25, 0.25), (5, 5), (30, 30), (60, 30)])
def test_deadline_reads_use_one_explicit_transaction_without_retries(monkeypatch, timeout, expected):
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value
    transaction = session.begin_transaction.return_value.__enter__.return_value
    transaction.run.return_value = [{"value": 2}]
    store = GraphStore("bolt://localhost:7687")
    monkeypatch.setattr(store, "connect", lambda: driver)
    assert store.read("RETURN $value AS value", timeout=timeout, value=2) == [{"value": 2}]
    driver.session.assert_called_once_with(database="neo4j", default_access_mode="READ")
    session.begin_transaction.assert_called_once_with(timeout=expected)
    transaction.run.assert_called_once_with("RETURN $value AS value", value=2)
    session.execute_read.assert_not_called()


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_deadline_read_rejects_invalid_timeout_before_connecting(monkeypatch, timeout):
    store = GraphStore("bolt://localhost:7687")
    connect = MagicMock()
    monkeypatch.setattr(store, "connect", connect)
    with pytest.raises(ValueError, match="finite and positive"):
        store.read("RETURN 1", timeout=timeout)
    connect.assert_not_called()
