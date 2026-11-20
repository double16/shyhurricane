"""Operational summaries retain timing splits without logging captured content per record."""

import io
import json
import logging
import sqlite3
from contextlib import closing
from unittest.mock import MagicMock

import pytest
from test_inventory_reader import fact

from shyhurricane.graph import performance
from shyhurricane.graph.blob_store import BlobStore, initialize
from shyhurricane.graph.inventory_outbox import InventoryOutbox
from shyhurricane.graph.inventory_pipeline import InventoryPipeline
from shyhurricane.graph.inventory_reader import InventoryReader
from shyhurricane.graph.performance import commit_timing, count, label, measured, phase, timed
from shyhurricane.graph.shard_store import ShardStore

LOGGER = logging.getLogger("graph-metrics-test")


def test_periodic_metrics_bound_info_volume_and_preserve_debug_and_errors(caplog, monkeypatch):
    caplog.set_level(logging.INFO)
    clock = [0.0]
    monkeypatch.setattr(performance.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(performance.time, "perf_counter", lambda: clock[0])

    @measured("busy", LOGGER, summary_interval=60)
    def operation(fail=False):
        count("logical_bytes", 10)
        label(artifact_id="opaque-artifact")
        with phase("io"):
            if fail:
                raise ValueError("private content")

    for _ in range(1000):
        operation()
    assert summaries(caplog) == []
    clock[0] = 60
    operation()
    result = summaries(caplog)[0]
    assert result["aggregate"] and result["operations"] == 1001
    assert result["counts"] == {"logical_bytes": 10010}
    assert result["phase_seconds"] == {"io": 0}
    assert result["window_seconds"] == 60
    assert "opaque-artifact" not in caplog.text
    operation()
    assert len(summaries(caplog)) == 1
    caplog.set_level(logging.WARNING)
    with pytest.raises(ValueError):
        operation(True)
    assert caplog.records[-1].levelno == logging.WARNING
    assert summaries(caplog)[-1]["outcome"] == "error"
    assert "private content" not in caplog.text
    caplog.set_level(logging.DEBUG)
    operation()
    assert caplog.records[-1].levelno == logging.DEBUG
    assert summaries(caplog)[-1]["artifact_id"] == "opaque-artifact"
    caplog.set_level(logging.INFO)
    clock[0] = 120
    operation()
    assert summaries(caplog)[-1]["operations"] == 3


def summaries(caplog, event=None):
    values = [json.loads(record.getMessage().removeprefix("Graph performance "))
              for record in caplog.records if record.getMessage().startswith("Graph performance ")]
    return [value for value in values if event is None or value["event"] == event]


def test_phase_totals_rates_and_nested_scope_restore(caplog, monkeypatch):
    caplog.set_level(logging.INFO)
    clock = [10.0]
    monkeypatch.setattr(performance.time, "perf_counter", lambda: clock[0])

    @measured("child", LOGGER)
    @timed("decode")
    def child():
        count("records")
        clock[0] += 1

    @measured("parent", LOGGER)
    def parent():
        count("records", 2)
        with phase("io"):
            clock[0] += 2
        child()
        count("records", 3)
        count("stored_bytes", 9)
        label(stage="fixture")
        return "result"

    assert parent() == "result"
    first, second = summaries(caplog)
    assert first["records"] == 1 and first["phase_seconds"] == {"decode": 1}
    assert second["records"] == 5 and second["elapsed_seconds"] == 3
    assert second["phase_seconds"] == {"io": 2}
    assert second["records_per_second"] == 5 / 3
    assert second["stored_bytes_per_second"] == 3
    assert second["stage"] == "fixture"
    count("outside")
    label(stage="outside")
    performance.elapsed("outside", 10)
    with phase("outside"):
        assert timed("outside")(lambda: 7)() == 7
    assert performance._active.get() is None


def test_idle_disabled_zero_duration_and_threshold_logging(caplog, monkeypatch):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(performance.time, "perf_counter", lambda: 1.0)

    @measured("idle", LOGGER, quiet=True)
    def idle():
        count("records", 0)
        return False

    assert not idle() and summaries(caplog) == []

    @measured("small", LOGGER, minimum_bytes=100)
    def small():
        count("logical_bytes", 10)
        return 42

    assert small() == 42 and summaries(caplog) == []
    caplog.set_level(logging.DEBUG)
    assert small() == 42
    assert caplog.records[-1].levelno == logging.DEBUG
    assert "records_per_second" not in summaries(caplog)[0]
    caplog.clear()
    caplog.set_level(logging.ERROR)
    assert measured("disabled", LOGGER)(lambda: 8)() == 8
    assert summaries(caplog) == []


def test_error_preserves_exception_and_records_failed_phase_without_content(caplog, monkeypatch):
    caplog.set_level(logging.INFO)
    clock = [0.0]
    monkeypatch.setattr(performance.time, "perf_counter", lambda: clock[0])

    @measured("failure", LOGGER, quiet=True, minimum_bytes=100)
    def failed():
        with phase("network"):
            clock[0] += 4
            raise ValueError("private captured content")

    with pytest.raises(ValueError, match="private captured content"):
        failed()
    result = summaries(caplog)[0]
    assert result["outcome"] == "error" and result["error_type"] == "ValueError"
    assert result["phase_seconds"] == {"network": 4}
    assert "private captured content" not in caplog.text
    assert performance._active.get() is None


def test_commit_timing_preserves_commit_rollback_and_failed_commit(caplog):
    caplog.set_level(logging.INFO)
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("CREATE TABLE example(value INTEGER)")

        @measured("transaction", LOGGER)
        def transaction(fail=False):
            with commit_timing(connection):
                connection.execute("INSERT INTO example VALUES (1)")
                if fail:
                    raise ValueError("rollback")

        transaction()
        assert summaries(caplog)[-1]["phase_seconds"]["sqlite_commit"] >= 0
        with pytest.raises(ValueError):
            transaction(True)
        assert connection.execute("SELECT count(*) FROM example").fetchone() == (1,)
        assert "sqlite_commit" not in summaries(caplog)[-1]["phase_seconds"]

    class FailedCommit:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            raise sqlite3.OperationalError("commit unavailable")

    @measured("failed_commit", LOGGER)
    def failed_commit():
        with commit_timing(FailedCommit()):
            pass

    with pytest.raises(sqlite3.OperationalError):
        failed_commit()
    result = summaries(caplog)[-1]
    assert result["outcome"] == "error" and result["phase_seconds"]["sqlite_commit"] >= 0


def test_inventory_page_emits_one_summary_with_payload_splits(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    shards = ShardStore(tmp_path)
    try:
        records = [{"id": str(i), "manifest_id": str(i), "kind": "symbol", "secret": "private content"}
                   for i in range(500)]
        reference = shards.put(records)
        rows = [fact(str(i), shard=reference, position=i) for i in range(101)]

        def read(statement, **parameters):
            if "CREATE (p:GraphInventoryReadPin" in statement:
                return [{"revision": 1}]
            return rows

        reader = InventoryReader(read, shards, request_id="opaque-request")
        caplog.clear()
        result, cursor = reader.page("example.com", limit=100)
        summary = summaries(caplog, "inventory_read")
        assert len(summary) == 1 and len(result) == 100 and cursor == "99"
        value = summary[0]
        assert value["returned_records"] == value["records"] == 100
        assert value["shards_read"] == 1 and value["read_bytes"] > value["decoded_bytes"] > 0
        assert value["request_id"] == "opaque-request"
        assert {"inventory_query", "read_pin_create", "payload_io", "payload_metadata", "payload_decompress",
                "payload_verify", "payload_json"} <= value["phase_seconds"].keys()
        assert "private content" not in caplog.text and "example.com" not in caplog.text
        with shards.connection:
            shards.connection.execute("UPDATE graph_shards SET version=99")
        with pytest.raises(ValueError):
            reader.page("example.com")
        assert summaries(caplog, "inventory_read")[-1]["outcome"] == "error"
    finally:
        shards.close()


def test_compression_large_artifacts_and_deduplication_metrics(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite")) as connection:
        initialize(connection)
        blobs = BlobStore(connection)
        content = {"body": "private-content-" * 10000}
        with connection:
            reference = blobs.put("not logged", content)
        assert blobs.read(reference) == content
        write = summaries(caplog, "artifact_write")[-1]
        read = summaries(caplog, "artifact_read")[-1]
        assert write["logical_bytes"] > write["stored_bytes"] > 0
        assert write["phase_seconds"]["compress"] >= 0
        assert read["decoded_bytes"] > 100000 and read["phase_seconds"]["payload_json"] >= 0
        assert "private-content" not in caplog.text and "not logged" not in caplog.text
        shards = ShardStore(tmp_path, connection)
        record = [{"manifest_id": "fact", "kind": "symbol"}]
        ref = shards.put(record)
        assert shards.put(record) == ref
        results = summaries(caplog, "shard_write")
        assert results[-2]["shards_written"] == 1 and results[-1]["shards_reused"] == 1
        assert results[-1]["records"] == 1
        assert {"serialize", "compress", "persist"} <= results[-1]["phase_seconds"].keys()
        shards.close()


def test_delivery_metrics_distinguish_remote_write_and_receipt_replay(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as connection:
        initialize(connection)
        shards = ShardStore(tmp_path, connection)
        outbox = InventoryOutbox(connection, shards)
        with connection:
            outbox.enqueue("generation", [{"manifest_id": "fact", "capture_id": "capture",
                                          "analysis_unit_id": "unit", "kind": "symbol"}])
        obligation = outbox.pending()[0]
        session, tx = MagicMock(), MagicMock()
        tx.run.return_value.single.side_effect = [
            {"state": "staging"}, None,
            {"state": "active"}, {"shard": obligation[3], "sequence": 0, "generation": "generation"},
        ]
        session.execute_write.side_effect = lambda function: function(tx)

        @measured("delivery", LOGGER)
        def deliver():
            with commit_timing(connection):
                outbox.deliver(session, obligation)

        deliver()
        deliver()
        first, second = summaries(caplog, "delivery")
        assert first["delivery"] == "write" and second["delivery"] == "replay"
        assert first["neo4j_attempts"] == second["neo4j_attempts"] == 1
        assert first["records"] == 1 and first["metadata_bytes"] > 0
        assert {"neo4j_write", "sqlite_ack", "sqlite_commit"} <= first["phase_seconds"].keys()
        shards.close()


def test_pipeline_does_not_log_idle_polling(graph_paths, caplog):
    from shyhurricane.graph.artifacts import ArtifactStore

    caplog.set_level(logging.INFO)
    artifacts = ArtifactStore("db")
    try:
        pipeline = InventoryPipeline(artifacts, MagicMock())
        assert not pipeline.step()
        assert summaries(caplog, "inventory_publish") == []
    finally:
        artifacts.close()


def test_compaction_and_reclamation_metrics_are_aggregated(tmp_path, monkeypatch, caplog):
    from test_segment_maintenance import add_shard

    from shyhurricane.graph import payload_store
    from shyhurricane.graph.segment_maintenance import SegmentMaintenance

    caplog.set_level(logging.INFO)
    monkeypatch.setattr(payload_store, "INLINE_BYTES", 0)
    monkeypatch.setattr(payload_store, "SEGMENT_BYTES", 100)
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as connection:
        initialize(connection)
        with connection:
            name = add_shard(connection, b"live" * 2, "live", pinned=True)
            add_shard(connection, b"x" * 92, "dead")
        root = tmp_path / "payload_segments"
        with (root / name).open("ab") as stream:
            stream.write(b"tail")
        (root / ("0" * 32 + ".pack")).write_bytes(b"orphan")
        maintenance = SegmentMaintenance(tmp_path)
        try:
            maintenance.tick(connection)
            value = summaries(caplog, "segment_maintenance")[-1]
            assert value["copy_records"] == 1 and value["copy_bytes"] == 8
            assert value["shards_deleted"] == value["orphan_files_deleted"] == 1
            assert value["tail_bytes_trimmed"] == 4 and value["copy_bytes_per_second"] >= 0
            assert {"segment_copy", "sqlite_lock", "sqlite_commit"} <= value["phase_seconds"].keys()
            maintenance.tick(connection)
            with connection:
                connection.execute("UPDATE graph_payload_segments SET retired_at=0 WHERE state='retired'")
            maintenance.tick(connection)
            assert any(row.get("segments_deleted") == 1 for row in summaries(caplog, "segment_maintenance"))
        finally:
            maintenance.close()


def test_disabled_parser_logging_forwards_bounded_cumulative_metrics(tmp_path, monkeypatch):
    path = tmp_path / "parser.stages"
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(path))
    clock = [0.0]
    monkeypatch.setattr(performance.time, "monotonic", lambda: clock[0])
    disabled = logging.root.manager.disable
    performance.flush_child_metrics()

    @measured("shard_write", LOGGER)
    def work(fail=False):
        count("records", 500)
        label(shard_id="private label")
        with phase("compress"):
            if fail:
                raise ValueError("private content")

    try:
        logging.disable(logging.CRITICAL)
        work()
        snapshots = [json.loads(line) for line in path.read_text().splitlines()]
        assert snapshots[0]["counts"]["records"] == 500 and not snapshots[0]["final"]
        clock[0] = 31
        with pytest.raises(ValueError):
            work(True)
        for index in range(20):
            measured(f"event-{index}", LOGGER)(lambda: count("records"))()
        performance.flush_child_metrics()

        snapshots = [json.loads(line) for line in path.read_text().splitlines()]
        final = [value for value in snapshots if value["final"]]
        assert len(final) <= 8
        shard = next(value for value in final if value["event"] == "shard_write")
        assert shard["counts"]["records"] == 1000 and shard["operations"] == 2
        assert shard["failed_operations"] == 1 and shard["phase_seconds"]["compress"] >= 0
        assert "private" not in path.read_text()
        assert len(path.read_bytes()) < 8192
        assert not performance._child_totals
        # A missing diagnostic directory must not fail analysis or retain process-global totals.
        monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(tmp_path / "missing" / "stages"))
        work()
        performance.flush_child_metrics()
        assert not performance._child_totals
    finally:
        logging.disable(disabled)
        performance.flush_child_metrics()


def test_parser_main_flushes_metrics_before_serializing_result(tmp_path, event, monkeypatch):
    from shyhurricane.graph import parser_worker
    from shyhurricane.graph.model import Projection

    output, diagnostics = tmp_path / "out.json", tmp_path / "out.stages"
    capture = event()
    request = {"event": capture, "root": str(tmp_path), "output": str(output),
               "snapshot_path": "snapshot", "document_contexts": [], "open_world": False}
    monkeypatch.setattr(parser_worker.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(diagnostics))
    monkeypatch.setattr("shyhurricane.graph.epoch_catalog.SnapshotArtifacts", lambda *args: MagicMock())

    @measured("shard_write", LOGGER)
    def extract(*args, **kwargs):
        count("records", 500)
        return Projection(capture)

    monkeypatch.setattr("shyhurricane.graph.extract.extract", extract)
    disabled = logging.root.manager.disable
    try:
        parser_worker.main()
    finally:
        logging.disable(disabled)
    lines = [json.loads(line) for line in diagnostics.read_text().splitlines()]
    result = next(value for value in lines if value["stage"] == "performance" and value["final"])
    assert result["counts"]["records"] == 500 and result["operations"] == 1
    assert json.loads(output.read_text())["event"]["id"] == capture["id"]
