"""Read-only recovery export and replay compatibility."""

import copy
import hashlib
import json
import sqlite3
import stat
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from shyhurricane import export_ingestion as ex


def capture(**overrides):
    data = {
        "url": "https://example.com/a",
        "timestamp": "2026-10-19T12:00:00+00:00",
        "method": "POST",
        "request_headers": {"Cookie": "private"},
        "response_headers": {"Content-Type": "text/html"},
        "request_body": "important",
        "response_body": "<html> original </html>",
        "response_code": 200,
        "technologies": [],
        "forms": None,
        "response_rtt": 12.0,
    }
    return data | overrides


def graph(root, events):
    directory = root / "graph_state"
    directory.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(directory / "artifacts.sqlite")) as db, db:
        db.execute("CREATE TABLE captures (id TEXT PRIMARY KEY, path TEXT)")
        for index, event in enumerate(events):
            identifier = str(index)
            path = directory / f"{identifier}.json"
            path.write_text(json.dumps({"id": identifier, **event}))
            # Simulate artifacts copied from a container's /data mount.
            db.execute("INSERT INTO captures VALUES (?,?)", (identifier, f"/data/graph_state/{path.name}"))
    return directory


def point(kind="content", data=None, identifier="p1", **overrides):
    data = data or capture()
    meta = {
        "url": data["url"],
        "timestamp": data["timestamp"],
        "http_method": data["method"],
        "status_code": data["response_code"],
        "request_headers": json.dumps(data["request_headers"]),
        "response_headers": json.dumps(data["response_headers"]),
        "technologies": "[]",
        "response_rtt": data["response_rtt"],
        "content_sha256": hashlib.sha256((data["response_body"] or "").encode()).hexdigest(),
    }
    body = data["response_body"]
    if kind == "forms":
        body = json.dumps(data["forms"])
        meta.pop("request_headers")
        meta.pop("response_headers")
    return SimpleNamespace(id=identifier, payload={"meta": meta, "content": body} | overrides)


def client_for(collections):
    client = MagicMock(spec=["collection_exists", "scroll", "close"])
    client.collection_exists.side_effect = lambda name: name in collections
    client.scroll.side_effect = lambda **kwargs: (collections[kwargs["collection_name"]], None)
    return client


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def run_export(tmp_path, monkeypatch):
    def run(collections=None, events=None):
        root = tmp_path / "data"
        if events is not None:
            graph(root, events)
        client = client_for(collections or {})
        monkeypatch.setattr(ex, "open_qdrant", lambda **kwargs: client)
        output = tmp_path / "export"
        code = ex.export(root, output, qdrant_url="http://localhost:6333")
        return code, output, json.loads((output / "export-report.json").read_text()), client

    return run


def test_graph_export_preserves_every_field_and_is_private(tmp_path):
    data = capture(forms=[{"action": "/submit", "method": "POST"}])
    root = tmp_path / "data"
    directory = graph(root, [{"data": data}, {"data": data}, {"data": capture(response_body="other")}])
    baseline = {p.name: p.read_bytes() for p in directory.iterdir()}
    output = tmp_path / "out"
    assert ex.export(root, output, graph_only=True) == 0
    records = lines(output / "index.jsonl")
    assert len(records) == 2
    assert ex.katana(data) in records
    assert not lines(output / "findings.jsonl")
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == baseline
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in output.iterdir())
    # Verify the actual application's Katana parser accepts the recovered exchange.
    from shyhurricane.index.input_documents import KatanaDocument

    parsed = KatanaDocument().run((output / "index.jsonl").read_text())["request_responses"]
    assert len(parsed) == 2
    assert any(item.request_body == "important" for item in parsed)


def test_graph_preferred_to_normalized_content_and_backfill(run_export):
    data = capture()
    normalized = point(content="<html>original</html>")
    normalized.payload["meta"]["response_headers"] = json.dumps(data["response_headers"] | {"Content-Length": "21"})
    code, output, report, client = run_export(
        {"content": [normalized], "network": [point("network")]},
        [{"data": data}, {"data": data | {"request_body": None}, "backfill": True}],
    )
    assert code == 0
    assert lines(output / "index.jsonl") == [ex.katana(data)]
    assert report["duplicates"] == 3
    for call in client.scroll.call_args_list:
        assert call.kwargs["with_vectors"] is False
        assert call.kwargs["limit"] == 100


def test_qdrant_only_merges_unambiguous_forms(run_export):
    data = capture(forms=[{"action": "/send"}])
    code, output, report, _ = run_export({kind: [point(kind, data)] for kind in ("content", "network", "forms")})
    assert code == 0
    records = lines(output / "index.jsonl")
    assert len(records) == 1
    assert records[0]["response"]["forms"] == data["forms"]
    assert records[0]["request"]["body"] is None
    assert report["warnings"]


def test_ambiguous_content_and_forms_preserved(run_export):
    code, output, report, _ = run_export(
        {
            "content": [point(), point(data=capture(response_body="different"), identifier="p2")],
            "forms": [
                point("forms", capture(forms=[{"action": "/one"}])),
                point("forms", capture(forms=[{"action": "/two"}]), identifier="f2"),
            ],
        }
    )
    assert code == 0
    assert len(lines(output / "index.jsonl")) == 4
    assert report["ambiguous_groups"] == 1


def test_header_variants_and_unmatched_backfills_survive(run_export):
    data = capture()
    other = capture(request_headers={"Cookie": "different"})
    code, output, _, _ = run_export(
        {"content": [point(data=other)]}, [{"data": data}, {"data": capture(response_body="old"), "backfill": True}]
    )
    assert code == 0
    assert len(lines(output / "index.jsonl")) == 3


def test_network_only_and_null_binary_body(run_export):
    _, output, _, _ = run_export({"network": [point("network", capture(response_body=None))]})
    record = lines(output / "index.jsonl")[0]
    assert record["response"]["body"] is None
    assert record["response"]["headers"]["Content-Type"] == "text/html"


@pytest.mark.parametrize(
    "target_meta,expected",
    [
        ({"url": "https://example.com/a"}, "https://example.com/a"),
        ({"netloc": "[::1]:8443"}, "[::1]:8443"),
        ({"host": "::1"}, "[::1]"),
        ({"domain": "example.com"}, "example.com"),
    ],
)
def test_findings_replay_shape_and_provenance(run_export, target_meta, expected):
    finding = SimpleNamespace(
        id="finding-id",
        payload={"content": "# Evidence\nFull markdown", "meta": target_meta | {"timestamp": "then", "title": "Issue"}},
    )
    code, output, report, _ = run_export({"finding": [finding]})
    assert code == 0
    assert lines(output / "findings.jsonl") == [
        {"target": expected, "title": "Issue", "markdown": "# Evidence\nFull markdown"}
    ]
    assert report["finding_provenance"] == [{"id": "finding-id", "point_id": "finding-id", "timestamp": "then"}]


@pytest.mark.parametrize(
    "meta,body",
    [
        ({}, "text"),
        ({"host": "example.com"}, " "),
        ({"host": "bad host"}, "text"),
        ({"host": "example.com", "title": []}, "text"),
        ({"netloc": "example.com:wrong"}, "text"),
    ],
)
def test_invalid_findings_reported(run_export, meta, body):
    p = SimpleNamespace(id="bad", payload={"meta": meta, "content": body})
    code, output, report, _ = run_export({"finding": [p]})
    assert code == 2
    assert not lines(output / "findings.jsonl")
    assert report["issues"][0]["id"] == "bad"


def test_corrupt_graph_and_payloads_are_redacted(run_export):
    bad = SimpleNamespace(id="bad", payload={"meta": {"url": "secret-cookie"}})
    code, _, report, _ = run_export({"content": [bad]}, [{"data": {"url": "secret-cookie"}}])
    assert code == 2
    assert report["skipped_records"] == 2
    assert "secret-cookie" not in json.dumps(report)


def test_missing_and_mismatched_artifacts(tmp_path):
    root = tmp_path / "data"
    directory = graph(root, [{"data": capture()}, {"data": capture()}])
    (directory / "0.json").unlink()
    (directory / "1.json").write_text('{"id":"wrong"}')
    out = tmp_path / "out"
    assert ex.export(root, out, graph_only=True) == 2
    assert json.loads((out / "export-report.json").read_text())["skipped_records"] == 2


def test_symlink_escape_is_skipped(tmp_path):
    root = tmp_path / "data"
    directory = graph(root, [{"data": capture()}])
    outside = tmp_path / "outside.json"
    (directory / "0.json").rename(outside)
    (directory / "0.json").symlink_to(outside)
    assert ex.export(root, tmp_path / "out", graph_only=True) == 2


def test_pagination_and_cleanup_on_connection_failure(tmp_path, monkeypatch):
    client = client_for({"content": []})
    client.scroll.side_effect = [([point()], "next"), ([], None)]
    monkeypatch.setattr(ex, "open_qdrant", lambda **kwargs: client)
    output = tmp_path / "out"
    assert ex.export(tmp_path, output, qdrant_url="http://localhost:6333") == 0
    assert client.scroll.call_args_list[1].kwargs["offset"] == "next"
    client.scroll.side_effect = RuntimeError("secret")
    assert (
        ex.main(
            [
                "--data-dir",
                str(tmp_path),
                "--output-dir",
                str(tmp_path / "failed"),
                "--qdrant-url",
                "http://localhost:6333",
            ]
        )
        == 1
    )
    assert not (tmp_path / "failed").exists()
    assert not list(tmp_path.glob(".ingestion-export-*"))


def test_existing_output_and_main_errors(tmp_path, capsys):
    with pytest.raises(FileExistsError):
        ex.export(tmp_path, tmp_path, graph_only=True)
    assert ex.main(["--data-dir", str(tmp_path), "--output-dir", str(tmp_path), "--graph-only"]) == 1
    assert "No export was published" in capsys.readouterr().err
    assert ex.main(["--data-dir", str(tmp_path), "--output-dir", str(tmp_path / "new"), "--graph-only"]) == 0


def test_atomic_publish_failure(tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("publish failed")

    monkeypatch.setattr(ex.os, "replace", fail)
    with pytest.raises(OSError):
        ex.export(tmp_path, tmp_path / "out", graph_only=True)
    assert not (tmp_path / "out").exists()


def test_determinism_and_timestamp_order(tmp_path, monkeypatch):
    data = capture()
    earlier = capture(timestamp="2026-10-19T13:00:00+02:00", response_body="earlier")
    client = client_for({"content": [point(data=data), point(data=earlier, identifier="2")]})
    monkeypatch.setattr(ex, "open_qdrant", lambda **kwargs: client)
    for name in ("a", "b"):
        ex.export(tmp_path, tmp_path / name, qdrant_url="http://localhost:6333")
    assert (tmp_path / "a/index.jsonl").read_bytes() == (tmp_path / "b/index.jsonl").read_bytes()
    assert lines(tmp_path / "a/index.jsonl")[0]["response"]["body"] == "earlier"


@pytest.mark.parametrize(
    "change",
    [
        {"url": "ftp://example.com/a"},
        {"method": ""},
        {"response_code": 999},
        {"request_body": {}},
        {"timestamp": "yesterday"},
        {"request_headers": []},
        {"response_headers": {"X": []}},
    ],
)
def test_capture_validation(change):
    with pytest.raises((ValueError, TypeError)):
        ex.katana(capture(**change))


def test_partial_match_request_body_and_response():
    full = ex.katana(capture())
    partial = copy.deepcopy(full)
    partial["request"]["body"] = "different"
    assert not ex.partial_match(partial, full)
    partial["request"]["body"] = None
    assert ex.partial_match(partial, full)
    partial["response"]["forms"] = [{}]
    assert not ex.partial_match(partial, full)


def test_endpoint_resolution(tmp_path, monkeypatch):
    monkeypatch.delenv("QDRANT", raising=False)
    assert ex.endpoint(tmp_path, "http://explicit:6333") == "http://explicit:6333"
    monkeypatch.setenv("QDRANT", "remote:6333")
    assert ex.endpoint(tmp_path) == "http://remote:6333"
    monkeypatch.delenv("QDRANT")
    inspected = {
        "State": {"Running": True},
        "NetworkSettings": {"Ports": {"6333/tcp": [{"HostIp": "::1", "HostPort": "1234"}]}},
    }
    runner = MagicMock(return_value=SimpleNamespace(stdout=json.dumps([inspected])))
    monkeypatch.setattr(ex.subprocess, "run", runner)
    assert ex.endpoint(tmp_path) == "http://[::1]:1234"
    assert runner.call_args.args[0][:2] == ["docker", "inspect"]
    inspected["NetworkSettings"]["Ports"]["6333/tcp"][0]["HostIp"] = "0.0.0.0"
    runner.return_value.stdout = json.dumps([inspected])
    assert ex.endpoint(tmp_path) == "http://127.0.0.1:1234"
    inspected["State"]["Running"] = False
    runner.return_value.stdout = json.dumps([inspected])
    with pytest.raises(ValueError, match="stopped"):
        ex.endpoint(tmp_path)


def test_graph_backup_deadline(tmp_path, monkeypatch):
    graph(tmp_path, [{"data": capture()}])
    times = iter([0, 301])
    monkeypatch.setattr(ex.time, "monotonic", lambda: next(times))
    with pytest.raises(TimeoutError):
        ex.export(tmp_path, tmp_path / "out", graph_only=True)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"technologies": "bad"},
        {"technologies": [{}]},
        {"forms": ["bad"]},
        {"response_rtt": "slow"},
        {"response_rtt": -1},
        {"response_rtt": float("nan")},
    ],
)
def test_optional_capture_fields_rejected(change):
    with pytest.raises(ValueError):
        ex.katana(capture(**change))


def test_ipv6_legacy_netloc_recovered(run_export):
    p = SimpleNamespace(
        id="ipv6",
        payload={"content": "Finding", "meta": {"host": "2001:db8::1", "port": 8443, "netloc": "2001:db8::1:8443"}},
    )
    code, output, _, _ = run_export({"finding": [p]})
    assert code == 0
    assert lines(output / "findings.jsonl")[0]["target"] == "[2001:db8::1]:8443"


def test_live_wal_captures_are_included(tmp_path):
    directory = graph(tmp_path, [])
    path = directory / "capture.json"
    path.write_text(json.dumps({"id": "wal", "data": capture()}))
    with closing(sqlite3.connect(directory / "artifacts.sqlite")) as writer, writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("INSERT INTO captures VALUES (?,?)", ("wal", str(path)))
        writer.commit()
        assert (directory / "artifacts.sqlite-wal").exists()
        assert ex.export(tmp_path, tmp_path / "out", graph_only=True) == 0
        assert len(lines(tmp_path / "out/index.jsonl")) == 1
        assert writer.execute("SELECT count(*) FROM captures").fetchone()[0] == 1


def test_findings_accepted_by_existing_ingest_cli(tmp_path, monkeypatch):
    import io

    import ingest

    records = [{"target": "[::1]:8443", "title": "Issue", "markdown": "Evidence"}]
    monkeypatch.setattr(ingest.sys, "stdin", io.StringIO("\n".join(json.dumps(r) for r in records)))
    post = MagicMock()
    monkeypatch.setattr(ingest.requests, "post", post)
    assert ingest.main(["--mcp-url", "http://localhost:8000", "--katana"]) == 0
    assert post.call_args.args[0] == "http://localhost:8000/findings"
    assert json.loads(post.call_args.kwargs["data"]) == records[0]


def test_request_content_length_is_not_normalization_metadata(run_export):
    data = capture(request_headers={"Content-Length": "10"})
    variant = point(data=capture(request_headers={"Content-Length": "20"}))
    _, output, _, _ = run_export({"content": [variant]}, [{"data": data}])
    assert len(lines(output / "index.jsonl")) == 2


def test_forms_not_attached_when_graph_or_network_is_an_alternative(run_export):
    data = capture(forms=[{"action": "/send"}])
    _, output, report, _ = run_export(
        {"content": [point(data=data)], "forms": [point("forms", data)]},
        [{"data": capture(response_body="different")}],
    )
    assert len(lines(output / "index.jsonl")) == 3
    assert report["ambiguous_groups"] == 1
    content = next(r for r in lines(output / "index.jsonl") if r["response"]["body"] == data["response_body"])
    assert "forms" not in content["response"]


def test_graph_only_does_not_connect_or_inspect(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected source/service initialization")

    monkeypatch.setattr(ex, "open_qdrant", forbidden)
    monkeypatch.setattr(ex.subprocess, "run", forbidden)
    monkeypatch.setattr(ex, "endpoint", forbidden)
    graph(tmp_path, [{"data": capture()}])
    assert ex.export(tmp_path, tmp_path / "out", graph_only=True) == 0


def test_backfilled_network_body_is_unknown(run_export):
    data = capture()
    _, output, report, _ = run_export(
        {},
        [
            {"data": data},
            {"data": capture(request_body=None, response_body=""), "backfill": True},
        ],
    )
    assert lines(output / "index.jsonl") == [ex.katana(data)]
    assert report["source_records"]["backfill"] == 1


def test_qdrant_factory_uses_only_requested_connection(monkeypatch):
    import qdrant_client

    factory = MagicMock()
    monkeypatch.setattr(qdrant_client, "QdrantClient", factory)
    assert ex.open_qdrant(url="http://localhost:6333", timeout=30) is factory.return_value
    factory.assert_called_once_with(url="http://localhost:6333", timeout=30)


def test_original_document_id_preserved_in_finding_provenance(run_export):
    p = SimpleNamespace(
        id="qdrant-uuid", payload={"id": "original-id", "content": "Evidence", "meta": {"host": "example.com"}}
    )
    _, _, report, _ = run_export({"finding": [p]})
    assert report["finding_provenance"][0]["id"] == "original-id"
    assert report["finding_provenance"][0]["point_id"] == "qdrant-uuid"


def test_original_unicode_surrogate_survives_normalized_hash_matching(run_export):
    data = capture(response_body="a\ud800bc")
    normalized = point(content="abc")
    normalized.payload["meta"]["content_sha256"] = hashlib.sha256(b"abc").hexdigest()
    _, output, _, _ = run_export({"content": [normalized]}, [{"data": data}])
    assert lines(output / "index.jsonl") == [ex.katana(data)]


def test_installed_qdrant_client_lifecycle(tmp_path, monkeypatch):
    from qdrant_client import QdrantClient

    client = QdrantClient(location=":memory:")
    close = MagicMock(wraps=client.close)
    monkeypatch.setattr(client, "close", close)
    monkeypatch.setattr(ex, "open_qdrant", lambda **kwargs: client)
    assert ex.export(tmp_path, tmp_path / "out", qdrant_url="http://localhost:6333") == 0
    close.assert_called_once_with()


def test_client_closed_when_collection_read_fails(tmp_path, monkeypatch):
    client = client_for({"content": []})
    client.scroll.side_effect = RuntimeError("read failed")
    monkeypatch.setattr(ex, "open_qdrant", lambda **kwargs: client)
    with pytest.raises(RuntimeError, match="read failed"):
        ex.export(tmp_path, tmp_path / "out", qdrant_url="http://localhost:6333")
    client.close.assert_called_once_with()
    assert not (tmp_path / "out").exists()


def test_graph_backup_accepts_work_longer_than_old_deadline(tmp_path, monkeypatch):
    graph(tmp_path, [{"data": capture()}])
    times = iter([0, 31])
    monkeypatch.setattr(ex.time, "monotonic", lambda: next(times))
    assert ex.export(tmp_path, tmp_path / "out", graph_only=True) == 0
    assert len(lines(tmp_path / "out/index.jsonl")) == 1
    report = json.loads((tmp_path / "out/export-report.json").read_text())
    assert report["graph_backup_timeout_seconds"] == 300


def test_custom_graph_backup_deadline(tmp_path, monkeypatch):
    graph(tmp_path, [{"data": capture()}])
    times = iter([0, 301])
    monkeypatch.setattr(ex.time, "monotonic", lambda: next(times))
    assert ex.export(tmp_path, tmp_path / "out", graph_only=True, graph_backup_timeout_seconds=600) == 0


def test_backup_timeout_cli_reports_actionable_progress(tmp_path, monkeypatch, capsys):
    graph(tmp_path, [{"data": capture()}])
    times = iter([0, 2])
    monkeypatch.setattr(ex.time, "monotonic", lambda: next(times))
    assert (
        ex.main(
            [
                "--data-dir",
                str(tmp_path),
                "--output-dir",
                str(tmp_path / "out"),
                "--graph-only",
                "--graph-backup-timeout-seconds",
                "1",
            ]
        )
        == 1
    )
    error = capsys.readouterr().err
    assert "exceeded 1 seconds" in error
    assert "pages copied" in error
    assert "--graph-backup-timeout-seconds" in error
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".ingestion-export-*"))


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "bad"])
def test_backup_timeout_cli_rejects_invalid_values(tmp_path, value):
    with pytest.raises(SystemExit) as error:
        ex.main(["--output-dir", str(tmp_path / "out"), f"--graph-backup-timeout-seconds={value}"])
    assert error.value.code == 2
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf")])
def test_backup_timeout_library_validation(tmp_path, value):
    with pytest.raises(ValueError, match="finite and greater than zero"):
        ex.export(tmp_path, tmp_path / "out", graph_only=True, graph_backup_timeout_seconds=value)
    assert not (tmp_path / "out").exists()
