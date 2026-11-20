"""Discovery archive slices preserve committed work across parser restarts."""

from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import archive_checkpoint
from shyhurricane.graph.archive_checkpoint import ArchiveCursor, ArchivePending
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.discovery_manifest import archive_ir


def records(artifacts):
    return [record for (reference,) in artifacts.connection.execute(
        "SELECT shard FROM graph_inventory_outbox ORDER BY rowid"
    ) for record in artifacts.manifest.shards.read(reference)]


def test_slices_resume_without_rewriting_nodes(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    raw = {"nodes": [{"id": str(i), "kind": "symbol"} for i in range(1200)], "edges": [], "gaps": []}
    written = []
    original = artifacts.manifest.facts

    def facts(unit, capture, records):
        written.extend(data["id"] for _, data in records)
        return original(unit, capture, records)

    monkeypatch.setattr(artifacts.manifest, "facts", facts)
    for _ in range(8):
        budget = iter([240, 0])
        monkeypatch.setattr(archive_checkpoint, "remaining_seconds", lambda: next(budget, 0))
        try:
            unit = archive_ir(artifacts, capture, capture["data"]["url"], "app.js", raw)
            break
        except ArchivePending:
            assert artifacts.connection.execute(
                "SELECT discovery FROM graph_manifest_units WHERE source_path='app.js'"
            ).fetchone()[0] == "pending"
            artifacts.close()
            artifacts = ArtifactStore("db")
            original = artifacts.manifest.facts
            monkeypatch.setattr(artifacts.manifest, "facts", facts)
    else:
        pytest.fail("Archive did not finish")
    assert len(written) == len(set(written)) == 1200
    assert artifacts.connection.execute(
        "SELECT discovery,flow FROM graph_manifest_units WHERE id=?", (unit,)
    ).fetchone() == ("complete", "complete")
    monkeypatch.setattr(archive_checkpoint, "remaining_seconds", lambda: 0)
    assert archive_ir(artifacts, capture, capture["data"]["url"], "app.js", raw) == unit
    assert len(written) == 1200
    assert artifacts.connection.execute(
        "SELECT phase,artifact FROM graph_archive_progress"
    ).fetchone() == (-1, "")
    artifacts.close()


def test_failed_batch_rolls_back_cursor_and_data_then_reopens(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    cursor = ArchiveCursor(artifacts, capture, "https://example.com/", "a.js", {}, [])
    unit = artifacts.manifest.unit(capture["id"], "a.js")

    def fail(selected):
        artifacts.manifest.facts(unit, capture["id"], [("symbol", {"name": str(i)}) for i in selected])
        raise ValueError("interrupted")

    before = len(records(artifacts))
    with pytest.raises(ValueError):
        cursor.run(0, list(range(500)), fail)
    assert artifacts.connection.execute("SELECT offset FROM graph_archive_progress").fetchone()[0] == 0
    assert len(records(artifacts)) == before
    artifacts.close()
    artifacts = ArtifactStore("db")
    cursor = ArchiveCursor(artifacts, capture, "https://example.com/", "a.js", {}, [])
    cursor.run(0, [1], lambda selected: artifacts.manifest.facts(
        unit, capture["id"], [("symbol", {"name": str(i)}) for i in selected]
    ))
    assert cursor.phase == 1
    cursor.run(0, [1], MagicMock(side_effect=AssertionError("replayed completed phase")))
    artifacts.close()


def test_bulk_matches_individual_facts_and_preserves_memberships(graph_paths, event, monkeypatch):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    unit = artifacts.manifest.unit(capture["id"], "a.js")
    items = [
        ("resource", {"url": "https://example.com/", "capture_status": "captured", "method": "post"}),
        ("symbol", {"name": "long" * 50, "context_capture_id": "context"}),
        ("symbol", {"owner_url": "https://example.com/", "role": "source"}),
        ("symbol", {"name": "long" * 50, "context_capture_id": "second-context"}),
    ]
    keys = artifacts.manifest.facts(unit, capture["id"], items)
    unique = {row["manifest_id"] for row in records(artifacts)}
    assert keys == [artifacts.manifest.fact(unit, capture["id"], kind, data) for kind, data in items]
    assert artifacts.manifest.facts(unit, capture["id"], items) == keys
    assert {row["manifest_id"] for row in records(artifacts)} == unique
    assert {context for row in records(artifacts) for context in row.get("_context_ids", [])} == {"context", "second-context"}
    assert artifacts.manifest.facts(unit, capture["id"], []) == []
    with pytest.raises(ValueError):
        artifacts.manifest.facts(unit, capture["id"], items * 200)
    artifacts.close()


def test_checkpoint_keys_and_analysis_pins_survive_cache_eviction(graph_paths, event):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    first = ArchiveCursor(artifacts, capture, "https://example.com/", "a.js", {"nodes": []}, [])
    changed = ArchiveCursor(artifacts, capture, "https://example.com/", "a.js", {"nodes": []}, [{"id": "ctx"}])
    assert first.key != changed.key
    factory = MagicMock(return_value={"archive": {"nodes": []}})
    assert artifacts.archive_analysis("analysis", factory) == factory.return_value
    with artifacts.connection:
        artifacts.connection.execute("DELETE FROM graph_cache")
    assert artifacts.archive_analysis("analysis", factory) == factory.return_value
    factory.assert_called_once()
    artifacts.release_archive_analysis("analysis")
    assert artifacts.connection.execute("SELECT count(*) FROM graph_archive_inputs").fetchone()[0] == 0
    artifacts.close()


def test_multiple_scripts_keep_analysis_pinned_until_extraction_finishes(graph_paths, event, monkeypatch):
    from shyhurricane.graph import extract as extraction

    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(body="<script>first()</script><script>second()</script>"))
    runner = MagicMock(return_value={"nodes": [], "edges": [], "references": [], "gaps": []})
    calls = []

    def archive(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise ArchivePending()
        return archive_ir(*args, **kwargs)

    monkeypatch.setattr(extraction, "archive_ir", archive)
    with pytest.raises(ArchivePending):
        extraction.extract(capture, artifacts, javascript_runner=runner)
    assert artifacts.connection.execute("SELECT count(*) FROM graph_archive_inputs").fetchone()[0] == 2
    with artifacts.connection:
        artifacts.connection.execute("DELETE FROM graph_cache")
    extraction.extract(capture, artifacts, javascript_runner=runner)
    assert runner.call_count == 2
    assert artifacts.connection.execute("SELECT count(*) FROM graph_archive_inputs").fetchone()[0] == 0
    artifacts.close()


def test_bulk_fact_sql_count_is_less_than_half_individual_writes(tmp_path):
    import sqlite3

    from shyhurricane.graph.blob_store import initialize
    from shyhurricane.graph.manifest import ManifestStore

    class CountingConnection(sqlite3.Connection):
        statements = 0

        def execute(self, *args, **kwargs):
            self.statements += 1
            return super().execute(*args, **kwargs)

        def executemany(self, sql, rows):
            rows = list(rows)
            self.statements += len(rows)
            return super().executemany(sql, rows)

    connection = sqlite3.connect(":memory:", factory=CountingConnection)
    initialize(connection)
    manifest = ManifestStore(connection, tmp_path)
    records = [("symbol", {"name": str(i), "url": "https://example.com/app.js"}) for i in range(500)]
    connection.statements = 0
    for kind, data in records:
        manifest.fact("individual", "capture", kind, data)
    individual = connection.statements
    connection.statements = 0
    manifest.facts("bulk", "capture", records)
    assert connection.statements < individual / 2
    manifest.flush()
    references = connection.execute("SELECT shard FROM graph_inventory_outbox").fetchall()
    assert sum(len(manifest.shards.read(ref)) for (ref,) in references) == 1000
    manifest.shards.close()
    connection.close()


def test_batch_splits_reconcile(graph_paths, event, tmp_path, monkeypatch):
    import json

    path = tmp_path / "timings"
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(path))
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event())
        cursor = ArchiveCursor(artifacts, capture, "https://example.com/", "timed.js", {}, [])
        unit = artifacts.manifest.unit(capture["id"], "timed.js")
        cursor.run(0, [1, 2], lambda selected: artifacts.manifest.facts(
            unit, capture["id"], [("symbol", {"name": str(i)}) for i in selected]
        ))
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        batch = next(row for row in rows if row["stage"] == "archive-batch")
        assert batch["rows"] == 2
        assert batch["sql_calls"] > 0
        assert all(batch[key] >= 0 for key in (
            "lock_seconds", "sql_seconds", "preparation_seconds", "commit_seconds",
        ))
        assert sum(batch[key] for key in (
            "lock_seconds", "sql_seconds", "preparation_seconds", "commit_seconds",
        )) == pytest.approx(batch["total_seconds"], abs=0.002)
    finally:
        artifacts.close()
