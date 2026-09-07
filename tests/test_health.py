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
