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