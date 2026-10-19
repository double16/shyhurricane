import pytest

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
        {"host": "127.0.0.1", "port": 6333},
        {"host": "127.0.0.1", "port": 6333},
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
        lambda: available["qdrant"], lambda: available["llm"],
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
