import json
import sqlite3
import subprocess

import pytest
from haystack import Document
from haystack.dataclasses import SparseEmbedding
from haystack.document_stores.types import DuplicatePolicy
from haystack_integrations.components.retrievers.qdrant import QdrantHybridRetriever
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client.local.persistence import CollectionPersistence

import shyhurricane.db as db


def test_qdrant_persistence_overwrite_filter_and_hybrid_retrieval(tmp_path, monkeypatch):
    # Qdrant's fallback probe uses a transaction context without closing its SQLite connection.
    # Python 3.11+ reports the same build setting directly (3 means serialized/THREADSAFE=1).
    monkeypatch.setattr(CollectionPersistence, "CHECK_SAME_THREAD", sqlite3.threadsafety != 3)
    settings = dict(path=str(tmp_path), index="retrieval", embedding_dim=2,
                    use_sparse_embeddings=True, return_embedding=True, similarity="dot_product")
    document = Document(content="dense and sparse", meta={"type": "network"}, embedding=[0.1, 0.2],
                        sparse_embedding=SparseEmbedding(indices=[1, 3], values=[0.5, 0.25]))
    store = QdrantDocumentStore(**settings)
    try:
        store.write_documents([document], policy=DuplicatePolicy.OVERWRITE)
    finally:
        store.close()

    store = QdrantDocumentStore(**settings)
    try:
        store.write_documents([document], policy=DuplicatePolicy.OVERWRITE)
        assert store.count_documents() == 1
        filters = {"field": "meta.type", "operator": "==", "value": "network"}
        restored = store.filter_documents(filters)[0]
        assert restored.id == document.id
        assert restored.meta == document.meta
        assert restored.embedding == pytest.approx(document.embedding)
        assert restored.sparse_embedding == document.sparse_embedding
        retriever = QdrantHybridRetriever(document_store=store, top_k=10)
        result = retriever.run(query_embedding=document.embedding,
                               query_sparse_embedding=document.sparse_embedding, filters=filters)
        assert [doc.id for doc in result["documents"]] == [document.id]
        assert retriever.run(query_embedding=document.embedding, query_sparse_embedding=document.sparse_embedding,
                             filters={"field": "meta.type", "operator": "==", "value": "absent"}) == {"documents": []}
    finally:
        store.close()


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
    monkeypatch.setattr(db, "_QDRANT_ENDPOINTS", {})

    assert db.qdrant_host_port("qdrant.local:6333") == ("qdrant.local", 6333)
    assert db.qdrant_host_port("qdrant.local:6333") == ("qdrant.local", 6333)


def test_qdrant_host_port_starts_docker_for_path(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "_QDRANT_ENDPOINTS", {})
    monkeypatch.setattr(
        db,
        "_start_qdrant_docker",
        lambda name, storage_dir: db.QdrantDockerInfo(name, "abc", "127.0.0.1", 1234, "127.0.0.1", 5678),
    )

    assert db.qdrant_host_port(str(tmp_path / "My DB!")) == ("127.0.0.1", 1234)


def test_qdrant_connections_and_container_names_are_isolated_by_full_path(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "_QDRANT_ENDPOINTS", {})
    calls = []

    def start(name, storage_dir):
        calls.append((name, storage_dir))
        return db.QdrantDockerInfo(name, "abc", "127.0.0.1", 10000 + len(calls), "127.0.0.1", 6334)

    monkeypatch.setattr(db, "_start_qdrant_docker", start)
    first, second = (str(tmp_path / name / "qdrant") for name in ("one", "two"))
    assert db.qdrant_host_port(first) == ("127.0.0.1", 10001)
    assert db.qdrant_host_port(second) == ("127.0.0.1", 10002)
    assert db.qdrant_host_port(first) == ("127.0.0.1", 10001)
    assert db.qdrant_host_port("remote:6333") == ("remote", 6333)
    assert db.qdrant_host_port("other:6334") == ("other", 6334)
    assert len(calls) == 2
    assert calls[0][0] != calls[1][0]
    assert [call[1] for call in calls] == [first, second]


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


def test_find_available_port_uses_requested_host_and_closes_socket(monkeypatch):
    calls = []

    class Socket:
        def getsockname(self):
            return ("127.0.0.1", 49201)

        def close(self):
            calls.append("closed")

    def create_server(address):
        calls.append(address)
        return Socket()

    monkeypatch.setattr(db.socket, "create_server", create_server)

    assert db._find_available_port("127.0.0.1") == 49201
    assert calls == [("127.0.0.1", 0), "closed"]


def test_find_available_port_propagates_binding_errors(monkeypatch):
    def create_server(address):
        raise OSError("address unavailable")

    monkeypatch.setattr(db.socket, "create_server", create_server)

    with pytest.raises(OSError, match="address unavailable"):
        db._find_available_port("127.0.0.1")


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
    created_info = docker_inspect()
    created_info["Mounts"] = [{"Source": str(tmp_path / "create"), "Destination": "/qdrant/storage"}]
    started_info = docker_inspect()
    started_info["Mounts"] = [{"Source": str(tmp_path / "start"), "Destination": "/qdrant/storage"}]
    inspect_values = iter([None, created_info, docker_inspect(running=False), started_info])

    def inspect(name):
        return next(inspect_values)

    monkeypatch.setattr(db, "_inspect_container", inspect)
    monkeypatch.setattr(db, "_run", lambda cmd, check=True: commands.append(cmd))
    ports = iter([49201, 49201, 49202])
    monkeypatch.setattr(db, "_find_available_port", lambda host: next(ports))

    created = db._start_qdrant_docker(name="qdrant-test", storage_dir=str(tmp_path / "create"), pull=True)
    started = db._start_qdrant_docker(name="qdrant-test", storage_dir=str(tmp_path / "start"))

    assert created.http_port == 63330
    assert started.grpc_port == 63340
    assert ["docker", "pull", "qdrant/qdrant:latest"] in commands
    assert any(cmd[:3] == ["docker", "run", "-d"] for cmd in commands)
    create_command = next(cmd for cmd in commands if cmd[:3] == ["docker", "run", "-d"])
    assert "127.0.0.1:49201:6333" in create_command
    assert "127.0.0.1:49202:6334" in create_command
    assert ["docker", "start", "qdrant-test"] in commands

    monkeypatch.setattr(db, "_inspect_container", lambda name: {"State": {"Running": True}})
    with pytest.raises(RuntimeError, match="container Id"):
        db._start_qdrant_docker(name="bad", storage_dir=str(tmp_path / "bad"))


def test_qdrant_reused_container_requires_matching_mount(monkeypatch, tmp_path):
    info = docker_inspect()
    monkeypatch.setattr(db, "_inspect_container", lambda name: info)
    with pytest.raises(RuntimeError, match="storage mount"):
        db._start_qdrant_docker(storage_dir=str(tmp_path))
    info["Mounts"] = [{"Destination": "/qdrant/storage", "Source": str(tmp_path / "elsewhere")}]
    with pytest.raises(RuntimeError, match="storage mount"):
        db._start_qdrant_docker(storage_dir=str(tmp_path))
    info["Mounts"][0]["Source"] = str(tmp_path)
    assert db._start_qdrant_docker(storage_dir=str(tmp_path)).http_port == 63330


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
