import pytest
from neo4j.exceptions import DatabaseError, DatabaseUnavailable, ServiceUnavailable, SessionExpired

import shyhurricane.health as health


def test_qdrant_probe_creates_a_new_client_after_a_connection_failure(monkeypatch):
    attempts = iter([ConnectionError("Qdrant is unavailable"), None])
    created = []

    class Client:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            created.append(self)

        def get_collections(self):
            if error := next(attempts):
                raise error

        def close(self):
            self.closed = True

    monkeypatch.setattr(health, "QdrantClient", Client)

    with pytest.raises(ConnectionError, match="unavailable"):
        health.qdrant_probe("127.0.0.1", 6333)

    assert health.qdrant_probe("127.0.0.1", 6333) is True
    assert [probe_client.kwargs for probe_client in created] == [
        {"host": "127.0.0.1", "port": 6333, "timeout": 5},
        {"host": "127.0.0.1", "port": 6333, "timeout": 5},
    ]
    assert all(probe_client.closed for probe_client in created)


def test_health_monitor_handles_llm_failure_and_stable_state():
    monitor = health.HealthMonitor(lambda: True, lambda: (_ for _ in ()).throw(RuntimeError("LLM unavailable")))

    assert monitor.check() is False
    assert monitor.qdrant_healthy is True
    assert monitor.llm_healthy is False
    assert monitor.ready.is_set() is False

    healthy = health.HealthMonitor(lambda: True, lambda: True)
    assert healthy.check() is True
    assert healthy.check() is True
    assert healthy.ready.is_set() is True

    stopped = health.HealthMonitor(lambda: True, lambda: True)
    stopped._stop.set()
    stopped._run()


def test_neo4j_outage_pauses_all_consumers_and_recovers():
    responses = iter([False, RuntimeError("down"), True])

    def probe():
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monitor = health.HealthMonitor(lambda: True, lambda: True, neo4j_probe=probe)
    assert not monitor.check()
    assert monitor.neo4j_healthy is False
    assert not monitor.ready.is_set()
    assert not monitor.check()
    assert monitor.check()
    assert monitor.ready.is_set()


def test_disk_gate_combines_dependencies_without_resetting_hysteresis(monkeypatch):
    from types import SimpleNamespace

    from shyhurricane.disk_space import DiskSpaceGuard
    from shyhurricane.server_config import ServerConfig

    capacity = SimpleNamespace(total=100 * 1024**3, free=1024**3)
    monkeypatch.setattr("shyhurricane.disk_space.shutil.disk_usage", lambda path: capacity)
    dependencies = [True]
    guard = DiskSpaceGuard("/data", ServerConfig())
    monitor = health.HealthMonitor(lambda: dependencies[0], lambda: True, disk_guard=guard)
    assert not monitor.ready.is_set()
    assert not monitor.check()
    dependencies[0] = False
    capacity.free = 3 * 1024**3
    assert not monitor.check()
    dependencies[0] = True
    assert not monitor.check()
    capacity.free = 4 * 1024**3
    assert monitor.check()
    assert monitor.ready.is_set()
    dependencies[0] = False
    assert not monitor.check()
    assert not monitor.ready.is_set()
    assert guard.snapshot()["state"] == "healthy"


@pytest.mark.parametrize("other_dependency", ["neo4j", "llm"])
def test_qdrant_recovery_respects_other_dependency_gates(other_dependency):
    available = {"qdrant": False, "neo4j": True, "llm": True}
    monitor = health.HealthMonitor(
        lambda: available["qdrant"],
        lambda: available["llm"],
        neo4j_probe=lambda: available["neo4j"],
    )
    assert not monitor.check()
    available[other_dependency] = False
    available["qdrant"] = True
    assert not monitor.check()
    assert monitor.qdrant_healthy is True
    assert not monitor.ready.is_set()
    available[other_dependency] = True
    assert monitor.check()
    available["qdrant"] = False
    assert not monitor.check()
    assert not monitor.ready.is_set()
    available["qdrant"] = True
    assert monitor.check()


@pytest.mark.parametrize(
    "database,error_factory",
    [
        (
            "Neo4j",
            lambda: ServiceUnavailable("Couldn't connect\nConnection closed"),
        ),
        (
            "Neo4j",
            lambda: DatabaseUnavailable("Database unavailable\nRetry later"),
        ),
        (
            "Neo4j",
            lambda: SessionExpired("Session expired"),
        ),
        (
            "Neo4j",
            lambda: DatabaseError("The database has encountered a critical error"),
        ),
        ("Qdrant", lambda: health.ResponseHandlingException(ConnectionError("Connection\nrefused"))),
        ("Qdrant", lambda: health.UnexpectedResponse(503, "Unavailable", b"Retry later", {})),
        ("Qdrant", lambda: health.TransportError("Connection\nlost")),
        ("Qdrant", lambda: ConnectionError("Connection\nrefused")),
        ("Qdrant", lambda: TimeoutError("Health request timed out")),
    ],
)
def test_known_database_health_failures_log_one_line_and_recover(database, error_factory, caplog):
    import logging

    error = error_factory()
    results = iter([True, error, True])

    def probe():
        result = next(results)
        if isinstance(result, Exception):
            try:
                raise OSError("original connection failure")
            except OSError as cause:
                raise result from cause
        return result

    monitor = health.HealthMonitor(
        probe if database == "Qdrant" else lambda: True,
        lambda: True,
        neo4j_probe=probe if database == "Neo4j" else lambda: True,
    )
    with caplog.at_level(logging.WARNING, logger="shyhurricane.health"):
        assert monitor.check()
        assert monitor.ready.is_set()
        assert not monitor.check()
        assert not monitor.ready.is_set()
        assert monitor.check()
        assert monitor.ready.is_set()
    records = [record for record in caplog.records if record.name == "shyhurricane.health"]
    assert len(records) == 1
    record = records[0]
    assert record.exc_info is None
    assert record.stack_info is None
    assert f"{database} health check failed ({type(error).__name__})" in record.getMessage()
    assert "\n" not in record.getMessage()
    assert "\r" not in record.getMessage()
    assert "Traceback" not in caplog.text
    assert "original connection failure" not in caplog.text
    assert monitor.qdrant_healthy is True
    assert monitor.neo4j_healthy is True


@pytest.mark.parametrize("database", ["Qdrant", "Neo4j"])
def test_unexpected_database_health_failures_keep_traceback(database, caplog):
    import logging

    def probe():
        raise ValueError("Unexpected programming error")

    monitor = health.HealthMonitor(
        probe if database == "Qdrant" else lambda: True,
        lambda: True,
        neo4j_probe=probe if database == "Neo4j" else lambda: True,
    )
    with caplog.at_level(logging.WARNING, logger="shyhurricane.health"):
        assert not monitor.check()
    record = next(record for record in caplog.records if record.name == "shyhurricane.health")
    assert record.exc_info[0] is ValueError
    assert "Traceback" in caplog.text
    assert not monitor.ready.is_set()


def test_health_monitor_background_loop_fails_closed_on_unexpected_error(monkeypatch, caplog):
    import logging

    monitor = health.HealthMonitor(lambda: True, lambda: True)
    monitor.ready.set()

    def check():
        monitor._stop.set()
        raise ValueError("Unexpected monitor failure")

    monkeypatch.setattr(monitor, "check", check)
    with caplog.at_level(logging.WARNING, logger="shyhurricane.health"):
        monitor._run()
    assert not monitor.ready.is_set()
    assert monitor.qdrant_healthy is False
    assert monitor.llm_healthy is False
    assert monitor.neo4j_healthy is False
    record = next(record for record in caplog.records if record.name == "shyhurricane.health")
    assert record.exc_info[0] is ValueError


def test_health_monitor_background_thread_starts_and_closes():
    import threading

    checked = threading.Event()

    def probe():
        checked.set()
        return True

    monitor = health.HealthMonitor(probe, lambda: True, interval=0.01)
    monitor.start()
    try:
        assert checked.wait(timeout=2)
    finally:
        monitor.close()
    assert not monitor._thread.is_alive()
