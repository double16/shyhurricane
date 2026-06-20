import json
import subprocess
import time

import pytest

import shyhurricane.db as db


def test_qdrant_docker_info_http_url():
    info = db.QdrantDockerInfo("qdrant", "abc", "127.0.0.1", 6333, "127.0.0.1", 6334)

    assert info.http_url == "http://127.0.0.1:6333"


def test_run_wraps_subprocess_run(monkeypatch):
    calls = []

    def run(cmd, check, stdout, stderr, text):
        calls.append((cmd, check, stdout, stderr, text))
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(db.subprocess, "run", run)

    result = db._run(["docker", "ps"], check=False)

    assert result.stdout == "ok"
    assert calls == [(["docker", "ps"], False, subprocess.PIPE, subprocess.PIPE, True)]


def test_inspect_container_returns_none_on_failure_and_first_record(monkeypatch):
    monkeypatch.setattr(db, "_run", lambda cmd, check=False: subprocess.CompletedProcess(cmd, 1, stdout=""))
    assert db._inspect_container("missing") is None

    monkeypatch.setattr(
        db,
        "_run",
        lambda cmd, check=False: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([{"Id": "abc"}])),
    )
    assert db._inspect_container("qdrant") == {"Id": "abc"}


def test_is_running_and_published_port_selection():
    inspect = {
        "State": {"Running": True},
        "NetworkSettings": {
            "Ports": {
                "6333/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "1234"},
                    {"HostIp": "127.0.0.1", "HostPort": "5678"},
                ]
            }
        },
    }

    assert db._is_running(inspect) is True
    assert db._get_published_port(inspect, "6333/tcp") == ("127.0.0.1", 5678)


def test_get_published_port_errors_for_missing_binding_or_port():
    with pytest.raises(RuntimeError, match="no published binding"):
        db._get_published_port({"NetworkSettings": {"Ports": {}}}, "6333/tcp")

    with pytest.raises(RuntimeError, match="missing HostPort"):
        db._get_published_port({"NetworkSettings": {"Ports": {"6333/tcp": [{"HostIp": ""}]}}}, "6333/tcp")


def test_qdrant_host_port_uses_cached_and_host_port(monkeypatch):
    monkeypatch.setattr(db, "_QDRANT_HOST", None)
    monkeypatch.setattr(db, "_QDRANT_HOST_PORT", None)

    assert db.qdrant_host_port("qdrant.local:6333") == ("qdrant.local", 6333)
    assert db.qdrant_host_port("ignored") == ("qdrant.local", 6333)


def test_qdrant_host_port_starts_docker_for_path(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "_QDRANT_HOST", None)
    monkeypatch.setattr(db, "_QDRANT_HOST_PORT", None)
    monkeypatch.setattr(
        db,
        "_start_qdrant_docker",
        lambda name, storage_dir: db.QdrantDockerInfo(name, "abc", "127.0.0.1", 1234, "127.0.0.1", 5678),
    )
    monkeypatch.setattr(db, "_wait_ready", lambda url: None)

    assert db.qdrant_host_port(str(tmp_path / "My DB!")) == ("127.0.0.1", 1234)


@pytest.mark.asyncio
async def test_scroll_qdrant_collection_stops_on_none_and_empty_point_id():
    class Offset:
        num = 0
        uuid = ""

    class Client:
        def __init__(self):
            self.calls = 0

        async def scroll(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return ["record-1"], Offset()
            return ["record-2"], None

    assert [record async for record in db.scroll_qdrant_collection(Client(), "network")] == ["record-1"]


def test_wait_ready_returns_on_200_and_times_out(monkeypatch):
    class Response:
        status_code = 200

    monkeypatch.setattr(db.requests, "get", lambda url, timeout: Response())
    db._wait_ready("http://127.0.0.1:6333", timeout_s=1)

    times = iter([0.0, 1.0])
    monkeypatch.setattr(db.time, "time", lambda: next(times))
    monkeypatch.setattr(db.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(db.requests, "get", lambda url, timeout: (_ for _ in ()).throw(db.requests.RequestException()))

    with pytest.raises(TimeoutError):
        db._wait_ready("http://127.0.0.1:6333", timeout_s=1)


def docker_inspect(container_id="abc", running=True):
    return {
        "Id": container_id,
        "State": {"Running": running},
        "NetworkSettings": {
            "Ports": {
                "6333/tcp": [{"HostIp": "127.0.0.1", "HostPort": "63330"}],
                "6334/tcp": [{"HostIp": "127.0.0.1", "HostPort": "63340"}],
            }
        },
    }


def test_start_qdrant_docker_creates_starts_reuses_and_errors(monkeypatch, tmp_path):
    commands = []
    inspect_values = iter([None, docker_inspect(), docker_inspect(running=False), docker_inspect()])

    def inspect(name):
        return next(inspect_values)

    monkeypatch.setattr(db, "_inspect_container", inspect)
    monkeypatch.setattr(db, "_run", lambda cmd, check=True: commands.append(cmd))

    created = db._start_qdrant_docker(name="qdrant-test", storage_dir=str(tmp_path / "create"), pull=True)
    started = db._start_qdrant_docker(name="qdrant-test", storage_dir=str(tmp_path / "start"))

    assert created.http_port == 63330
    assert started.grpc_port == 63340
    assert ["docker", "pull", "qdrant/qdrant:latest"] in commands
    assert any(cmd[:3] == ["docker", "run", "-d"] for cmd in commands)
    assert ["docker", "start", "qdrant-test"] in commands

    monkeypatch.setattr(db, "_inspect_container", lambda name: {"State": {"Running": True}})
    with pytest.raises(RuntimeError, match="container Id"):
        db._start_qdrant_docker(name="bad", storage_dir=str(tmp_path / "bad"))


def test_create_qdrant_store_client_and_list_collections(monkeypatch):
    created = {}

    class Client:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def get_collections(self):
            return type("Collections", (), {"collections": [
                type("Collection", (), {"name": "content"})(),
                type("Collection", (), {"name": "network"})(),
            ]})()

    class Store:
        def __init__(self, **kwargs):
            created.update(kwargs)

    monkeypatch.setattr(db, "qdrant_host_port", lambda database: ("host", 6333))
    monkeypatch.setattr(db, "AsyncQdrantClient", Client)
    monkeypatch.setattr(db, "QdrantDocumentStore", Store)

    import asyncio

    client = asyncio.run(db.create_qdrant_client("db"))
    store = db.create_qdrant_document_store("db", index="content")
    collections = asyncio.run(db.list_collections("db"))

    assert client.kwargs == {"host": "host", "port": 6333}
    assert isinstance(store, Store)
    assert created["host"] == "host"
    assert created["port"] == 6333
    assert created["index"] == "content"
    assert created["use_sparse_embeddings"] is True
    assert {"field_name": "meta.url", "field_schema": "keyword"} in created["payload_fields_to_index"]
    assert collections == ["content", "network"]
