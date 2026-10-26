"""Lossless compression, ownership, normalization, eviction, and failure recovery."""

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import threading

import pytest

from shyhurricane.graph import blob_store
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.blob_store import BlobStore, initialize, validate
from shyhurricane.graph.storage_maintenance import StorageMaintenance


@pytest.fixture
def storage(graph_paths, monkeypatch):
    monkeypatch.setattr(
        "shyhurricane.graph.storage_maintenance.persistent_queue_path", lambda db, name: graph_paths / name
    )
    store = ArtifactStore("db")
    yield store
    store.close()


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        {},
        [],
        {"$graph_text": "literal"},
        {"$graph_literal": {"$graph_text": "literal"}},
        {"html": "<p>é漢🙂</p>" * 1000},
        {"js": "function f(){ return 1; }\n" * 2000},
        {"css": "body { color: blue; }\n" * 1000},
        {"binary": os.urandom(10000).hex()},
        {"nested": ["body" * 1000, {"text": "body" * 1000}]},
    ],
)
def test_roundtrip_without_files(storage, value):
    ref = storage.write("test", value)
    assert storage.read(ref) == value
    assert not list(storage.root.glob("*.json"))
    assert storage.blobs.exists(ref)
    assert not storage.blobs.exists("missing")
    with pytest.raises(FileNotFoundError):
        storage.read("missing")


def test_content_deduplication_and_transactional_owners(storage, event):
    body = "<html>same response</html>" * 5000
    first = storage.register(event(body=body))
    second = storage.register(event(url="https://example.com/other", body=body))
    digest = hashlib.sha256(body.encode()).hexdigest()
    assert storage.connection.execute("SELECT count(*) FROM graph_blobs WHERE digest=?", (digest,)).fetchone() == (1,)
    for capture in (first, second):
        assert storage.latest(capture["data"]["url"]) == capture
    reference = storage.connection.execute("SELECT path FROM captures LIMIT 1").fetchone()[0]
    storage.delete(reference)
    assert storage.blobs.exists(reference)
    stats = storage.blobs.statistics()
    assert stats["stored_payload_bytes"] < stats["logical_payload_bytes"] / 5
    assert stats["retained_bytes"] > 0


def test_rollback_replacement_and_nested_liveness(storage):
    child = storage.write("child", {"source": "abc" * 2000})
    parent = storage.write("parent", {"ir_artifact": child})
    with storage.connection:
        storage.blobs.own("fixture", parent)
    storage.delete(child)
    assert storage.read(child)
    before = storage.read(parent)
    with pytest.raises(RuntimeError), storage.connection:
        storage.blobs.put(parent, {"new": True})
        storage.blobs.own("fixture", child)
        raise RuntimeError("crash")
    assert storage.read(parent) == before
    assert storage.connection.execute("SELECT ref FROM graph_object_owners WHERE owner='fixture'").fetchone() == (
        parent,
    )
    with storage.connection:
        storage.connection.execute("UPDATE graph_nodes SET created=0")
        storage.blobs.maintain(budget=0)
    assert storage.read(child)
    with storage.connection:
        storage.blobs.own("fixture", None)
        storage.blobs.maintain(budget=0)
        storage.blobs.maintain(budget=0)
    assert not storage.blobs.exists(parent)
    assert not storage.blobs.exists(child)
    assert storage.connection.execute("SELECT count(*) FROM graph_blobs").fetchone() == (0,)


def test_cache_lru_budget_and_retained_promotion(storage, monkeypatch):
    for index in range(3):
        storage.cached(str(index), lambda: {"value": str(index) * 3000})
    refs = [row[0] for row in storage.connection.execute("SELECT ref FROM graph_objects ORDER BY accessed")]
    storage.cached("0", lambda: pytest.fail("cache hit"))
    with storage.connection:
        storage.blobs.own("retained", refs[1])
        storage.connection.execute("UPDATE graph_nodes SET created=0")
        storage.blobs.maintain(budget=0)
    assert storage.blobs.exists(refs[1])
    assert not storage.blobs.exists(refs[0])
    assert not storage.blobs.exists(refs[2])
    assert storage.blobs.statistics()["cache_bytes"] == 0
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "-1")
    with pytest.raises(ValueError, match="non-negative"):
        storage.blobs.statistics()
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    assert storage.blobs.statistics()["cache_budget_bytes"] == 0


@pytest.mark.parametrize("fault", ["version", "codec", "size", "payload", "missing", "raw", "length"])
def test_corruption_and_limits(storage, fault):
    ref = storage.write("fault", {"body": "x" * 3000})
    digest = storage.connection.execute("SELECT digest FROM graph_objects WHERE ref=?", (ref,)).fetchone()[0]
    with storage.connection:
        if fault == "missing":
            storage.connection.execute("DELETE FROM graph_blobs WHERE digest=?", (digest,))
        elif fault == "raw":
            storage.connection.execute("UPDATE graph_blobs SET codec='raw',payload=? WHERE digest=?", (b"!", digest))
        elif fault == "length":
            storage.connection.execute("UPDATE graph_blobs SET size=size+1 WHERE digest=?", (digest,))
        else:
            column, value = {
                "version": ("version", 99),
                "codec": ("codec", "other"),
                "size": ("size", 10**12),
                "payload": ("payload", b"broken"),
            }[fault]
            storage.connection.execute(f"UPDATE graph_blobs SET {column}=? WHERE digest=?", (value, digest))
    with pytest.raises(ValueError):
        storage.read(ref)


def test_size_limits_and_raw_codec(storage, monkeypatch):
    ref = storage.write("small", None)
    assert storage.connection.execute("SELECT codec FROM graph_blobs").fetchone() == ("raw",)
    with pytest.raises(ValueError, match="size limit"):
        storage.read(ref, limit=1)
    monkeypatch.setattr(blob_store, "MAX_DECODED_BYTES", 10)
    with pytest.raises(ValueError, match="size limit"):
        storage.write("large", "long value" * 100)
    monkeypatch.setattr(blob_store, "MAX_DECODED_BYTES", 256 * 1024 * 1024)
    ref = storage.write("shared", ["a" * 1024] * 5)
    with pytest.raises(ValueError, match="size limit"):
        storage.read(ref, limit=2000)


def test_version_rejection_without_legacy_mutation(tmp_path):
    path = tmp_path / "old.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE captures (id TEXT)")
        with pytest.raises(ValueError, match="fresh assessment"):
            initialize(connection)
        with pytest.raises(ValueError, match="fresh assessment"):
            validate(connection)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("captures",)]
    with sqlite3.connect(":memory:") as connection:
        connection.execute("PRAGMA user_version=99")
        with pytest.raises(ValueError):
            initialize(connection)


def test_concurrent_cache_writers_and_reopen(storage):
    database = storage.root / "artifacts.sqlite"
    calls = []

    def worker(index):
        connection = sqlite3.connect(database, timeout=5)
        store = object.__new__(ArtifactStore)
        store.root, store.connection, store.budget = storage.root, connection, None
        store.blobs = BlobStore(connection)
        try:
            return store.cached("shared", lambda: calls.append(index) or {"body": "same" * 1000})
        finally:
            connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(worker, range(8)))
    assert len(calls) == 1
    assert all(value == results[0] for value in results)
    assert len(list(storage.root.glob("artifact-lock-*"))) <= 64
    with sqlite3.connect(database) as connection:
        validate(connection)
        ref = connection.execute("SELECT ref FROM graph_objects").fetchone()[0]
        assert BlobStore(connection).read(ref) == results[0]


def test_normalized_context_versions_and_fact_payloads(storage, event):
    capture = storage.register(event())
    units = [storage.manifest.unit(capture["id"], f"unit:{index}") for index in range(3)]
    context = {"id": capture["id"], "url": capture["data"]["url"], "base": "https://example.com/"}
    for unit in units:
        storage.manifest.contexts(unit, [context])
    storage.manifest.contexts(units[0], [{**context, "base": "https://example.com/other"}])
    assert storage.connection.execute("SELECT count(*) FROM graph_context_documents").fetchone() == (2,)
    assert storage.connection.execute("SELECT count(*) FROM graph_context_members").fetchone() == (4,)
    for unit in units:
        storage.manifest.fact(unit, capture["id"], "field", {"name": "same", "url": context["url"]})
    assert storage.connection.execute(
        "SELECT count(DISTINCT data) FROM graph_facts f " "JOIN graph_terms t ON t.key=f.kind_key WHERE t.value='field'"
    ).fetchone() == (1,)
    plan = storage.connection.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM graph_facts WHERE url_key="
        "(SELECT key FROM graph_terms WHERE value=?) ORDER BY id LIMIT 1000",
        (context["url"],),
    ).fetchall()
    assert any("graph_manifest_url" in row[3] for row in plan)
    assert all("SCAN graph_facts" not in row[3] for row in plan)


def test_storage_maintenance_statistics_and_busy_writer(storage):
    maintenance = StorageMaintenance("db")
    storage.cached("cache", lambda: {"body": "content" * 5000})
    with storage.connection:
        storage.connection.execute("UPDATE graph_cache SET accessed=0")
    before = maintenance.statistics()
    assert before["wal_bytes"] >= 0 and before["allocated_bytes"] > 0
    maintenance.tick(threading.Event())
    with sqlite3.connect(storage.root / "artifacts.sqlite") as writer:
        writer.execute("BEGIN IMMEDIATE")
        result = maintenance.tick(threading.Event())
        assert result["deferred"] and result["pending"]
        writer.rollback()
    maintenance.tick(threading.Event())
    with sqlite3.connect(storage.root / "artifacts.sqlite") as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert maintenance.statistics()["wal_bytes"] == 0


def test_missing_maintenance_database(graph_paths, monkeypatch):
    monkeypatch.setattr(
        "shyhurricane.graph.storage_maintenance.persistent_queue_path", lambda *args: graph_paths / "missing"
    )
    StorageMaintenance("db").tick(threading.Event())


def test_zero_cache_budget_and_oldest_eviction(storage, monkeypatch):
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "0")
    assert storage.cached("disabled", lambda: "value") == "value"
    assert not storage.connection.execute("SELECT 1 FROM graph_objects").fetchone()
    monkeypatch.setenv("GRAPH_ARTIFACT_CACHE_MAX_BYTES", "100000")
    storage.cached("first", lambda: "a" * 5000)
    storage.cached("second", lambda: "b" * 5000)
    with storage.connection:
        storage.blobs.maintain(budget=10**9)
    before = storage.blobs.statistics()["cache_bytes"]
    with storage.connection:
        storage.blobs.maintain(budget=before)
    assert storage.blobs.statistics()["cache_bytes"] == before
    with storage.connection:
        storage.blobs.maintain(budget=before - 1, batch=1)
    assert storage.blobs.statistics()["cache_bytes"] < before


def test_frame_header_and_aggregate_write_bounds(storage, monkeypatch):
    ref = storage.write("compressed", {"same": "content" * 1000})
    with storage.connection:
        storage.connection.execute("UPDATE graph_blobs SET size=1 WHERE codec='zstd'")
    with pytest.raises(ValueError, match="size"):
        storage.read(ref)
    monkeypatch.setattr(blob_store, "MAX_DECODED_BYTES", 2500)
    with pytest.raises(ValueError, match="size limit"):
        storage.write("too-much-shared-text", ["x" * 2000] * 2)


def test_killed_writer_rolls_back_and_reopens(storage):
    import subprocess
    import sys

    ref = storage.write("durable", {"source": "retained"})
    program = """
import os
import sqlite3
import sys
from shyhurricane.graph.blob_store import BlobStore
connection = sqlite3.connect(sys.argv[1])
connection.execute("BEGIN IMMEDIATE")
BlobStore(connection).put(sys.argv[2], {"source": "uncommitted"})
os._exit(0)
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(storage.root / "artifacts.sqlite"), ref], capture_output=True, timeout=15
    )
    assert result.returncode == 0
    assert storage.read(ref) == {"source": "retained"}


def test_owner_primary_key_change_releases_previous_owner(storage):
    ref = storage.write("unit", {"source": "retained"})
    with storage.connection:
        storage.connection.execute(
            "INSERT INTO graph_manifest_units(id,capture_id,source_path,discovery,flow,artifact,updated_at) "
            "VALUES ('before','capture','test','complete','complete',?,0)",
            (ref,),
        )
        storage.connection.execute("UPDATE graph_manifest_units SET id='after' WHERE id='before'")
    owners = storage.connection.execute("SELECT owner FROM graph_object_owners WHERE ref=?", (ref,)).fetchall()
    assert owners == [("graph_manifest_units:artifact:after",)]


def test_worker_removes_only_abandoned_parser_files(graph_paths, event, monkeypatch):
    from unittest.mock import MagicMock

    from shyhurricane.graph import worker
    from shyhurricane.persistent_queue import get_persistent_queue

    store = ArtifactStore("db")
    temporary = store.root / "parser-tmp"
    temporary.mkdir()
    (temporary / "abandoned.json").write_text("unfinished")
    (temporary / "directory").mkdir()
    retained = store.write("evidence", {"source": "retained"})
    store.close()
    queue = get_persistent_queue("db", "graph_queue", auto_resume=False)
    queue.close()
    monkeypatch.setattr(worker, "GraphStore", lambda location: MagicMock())
    monkeypatch.setattr(worker, "prepare_worker_process", lambda: None)
    stopped = threading.Event()
    stopped.set()
    worker.graph_worker("db", "graph", threading.Event(), stopped, False)
    assert not (temporary / "abandoned.json").exists()
    assert (temporary / "directory").is_dir()
    check = ArtifactStore("db")
    assert check.read(retained) == {"source": "retained"}
    check.close()


def test_catalog_allocation_reduces_repeated_context_and_payload_data(storage, event, tmp_path):
    """Compare the actual catalog to the previous repeated-string representation."""
    from contextlib import closing

    contexts = []
    for index in range(10):
        capture = storage.register(event(url=f"https://example.com/page/{index}"))
        contexts.append(
            {
                "id": capture["id"],
                "url": capture["data"]["url"],
                "base": "https://example.com/",
                "metadata": "shared context " * 150,
            }
        )
    with closing(sqlite3.connect(tmp_path / "repeated.sqlite")) as repeated:
        repeated.executescript(
            "CREATE TABLE contexts(unit TEXT,context TEXT,url TEXT,host TEXT,data TEXT,PRIMARY KEY(unit,context));"
            "CREATE TABLE facts(id TEXT PRIMARY KEY,unit TEXT,capture TEXT,kind TEXT,url TEXT,host TEXT,role TEXT,data TEXT);"
            "CREATE INDEX fact_url ON facts(url,id);CREATE INDEX fact_unit ON facts(unit,id);"
        )
        with storage.manifest.batch(), repeated:
            for index in range(100):
                unit = storage.manifest.unit(capture["id"], f"unit:{index}")
                storage.manifest.contexts(unit, contexts)
                repeated.executemany(
                    "INSERT INTO contexts VALUES (?,?,?,?,?)",
                    ((unit, context["id"], context["url"], "example.com", json.dumps(context)) for context in contexts),
                )
                for number in range(4):
                    payload = {
                        "id": f"field-{number}",
                        "name": "field",
                        "url": "https://example.com/api",
                        "description": "shared complete retained detail " * 100,
                    }
                    key = storage.manifest.fact(unit, capture["id"], "field", payload)
                    repeated.execute(
                        "INSERT INTO facts VALUES (?,?,?,?,?,?,?,?)",
                        (
                            key,
                            unit,
                            capture["id"],
                            "field",
                            payload["url"],
                            "example.com",
                            "",
                            json.dumps({"kind": "field", **payload}),
                        ),
                    )
        old_bytes = repeated.execute("PRAGMA page_count").fetchone()[0] * 4096
    compact_bytes = storage.connection.execute("PRAGMA page_count").fetchone()[0] * 4096
    assert compact_bytes < old_bytes * 0.7
    assert storage.connection.execute("SELECT count(*) FROM graph_context_documents").fetchone() == (10,)
    assert storage.connection.execute("SELECT count(*) FROM graph_context_members").fetchone() == (1000,)
    assert storage.connection.execute(
        "SELECT count(*) FROM graph_facts f JOIN graph_terms t " "ON t.key=f.kind_key WHERE t.value='field'"
    ).fetchone() == (400,)


def test_fresh_store_initialization_is_safe_for_concurrent_openers(graph_paths):
    def opener(index):
        store = ArtifactStore("db")
        try:
            assert store.connection.execute("PRAGMA user_version").fetchone() == (blob_store.VERSION,)
            return store.write(f"init-{index}", {"index": index})
        finally:
            store.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        assert len(set(executor.map(opener, range(8)))) == 8


def test_old_store_rejected_in_writable_and_readonly_modes(graph_paths):
    from shyhurricane.graph.budget import QueryBudget

    root = graph_paths / "graph_state"
    root.mkdir()
    artifact = root / "capture.json"
    artifact.write_text("{}")
    with pytest.raises(ValueError, match="fresh assessment"):
        ArtifactStore("db")
    assert artifact.read_text() == "{}"
    assert not (root / "artifacts.sqlite").exists()
    with sqlite3.connect(root / "artifacts.sqlite") as connection:
        connection.execute("CREATE TABLE captures(id TEXT)")
    with pytest.raises(ValueError, match="fresh assessment"):
        ArtifactStore("db")
    with pytest.raises(ValueError, match="fresh assessment"):
        ArtifactStore("db", readonly=True, budget=QueryBudget())


def test_cached_nested_parser_does_not_hold_parent_bucket_lock(storage):
    import subprocess
    import sys

    program = """
import sqlite3
import sys
from pathlib import Path
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.blob_store import BlobStore
store = object.__new__(ArtifactStore)
store.root, store.budget = Path(sys.argv[1]), None
store.connection = sqlite3.connect(store.root / "artifacts.sqlite")
store.blobs = BlobStore(store.connection)
assert store.cached("child-key", lambda: "value") == "value"
store.close()
"""

    def factory():
        result = subprocess.run([sys.executable, "-c", program, str(storage.root)], capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return {"completed": True}

    assert storage.cached("parent-key", factory) == {"completed": True}


def test_dead_expired_and_busy_cache_leases(storage, monkeypatch):
    from shyhurricane.graph import cache_leases

    with cache_leases.cache_lease(storage.root, "fixture"):
        pass
    path = storage.root / "cache-leases.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO leases VALUES ('expired',1,'old',0)")
        connection.execute("INSERT INTO leases VALUES ('dead',99999999,'old',999999999999)")
        connection.execute("INSERT INTO leases VALUES ('busy',?,'old',999999999999)", (os.getpid(),))
    with cache_leases.cache_lease(storage.root, "expired"):
        pass
    with cache_leases.cache_lease(storage.root, "dead"):
        pass

    def release(seconds):
        with sqlite3.connect(path) as connection:
            connection.execute("DELETE FROM leases WHERE ref='busy'")

    monkeypatch.setattr(cache_leases.time, "sleep", release)
    with pytest.raises(RuntimeError), cache_leases.cache_lease(storage.root, "busy"):
        raise RuntimeError("failed factory")
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM leases").fetchone() == (0,)


def test_large_resource_starting_with_reference_prefix_is_only_content(storage):
    value = "a:" + "f" * 100000
    reference = storage.write("content-prefix", {"body": value})
    assert storage.read(reference) == {"body": value}
    assert storage.connection.execute("SELECT count(*) FROM graph_object_links").fetchone() == (0,)


def test_successful_external_source_maps_survive_cache_eviction(storage, monkeypatch):
    mapping = json.dumps({"version": 3, "sources": ["source.js"], "sourcesContent": ["retained source"]})
    monkeypatch.setattr("shyhurricane.source_maps._fetch_map", lambda *args: mapping)
    assert storage.source_map("https://example.com/app.js", "source", {}, True) == mapping
    with storage.connection:
        storage.blobs.maintain(budget=0)
    monkeypatch.setattr("shyhurricane.source_maps._fetch_map", lambda *args: pytest.fail("offline"))
    assert storage.source_map("https://example.com/app.js", "source", {}, False) == mapping
    assert storage.blobs.statistics()["retained_bytes"] > 0


def test_artifacts_preserve_node_and_edge_iteration_order(storage):
    # Bounded planners iterate projection dictionaries; checkpointing must preserve that order.
    value = {"nodes": {"z": {"id": "z"}, "a": {"id": "a"}}, "edges": {"second": {}, "first": {}}}
    result = storage.read(storage.write("ordered-projection", value))
    assert list(result["nodes"]) == ["z", "a"]
    assert list(result["edges"]) == ["second", "first"]
