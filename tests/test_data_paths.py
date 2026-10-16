import argparse
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from shyhurricane import data_paths
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_path
from shyhurricane.result_pages import ResultPageStore
from shyhurricane.server_config import ServerConfig
from shyhurricane.utils import get_log_path, get_state_path


def child_paths(queue):
    queue.put((str(data_paths.resolve_data_dir()), str(persistent_queue_path("remote:6333", "ingest_queue"))))


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_data_detection_overrides_native_defaults(monkeypatch, platform):
    monkeypatch.setattr(data_paths.sys, "platform", platform)
    monkeypatch.setattr(Path, "is_dir", lambda path: path == Path("/data"))
    monkeypatch.delenv("DATA_DIR")
    assert data_paths.default_data_dir() == Path("/data")
    assert data_paths.resolve_data_dir("assessment") == Path("/data/assessment")
    assert data_paths.resolve_data_dir("/elsewhere") == Path("/elsewhere")


@pytest.mark.parametrize("platform,suffix", [
    ("linux", ".local/state/shyhurricane"),
    ("darwin", "Library/Application Support/shyhurricane"),
    ("win32", "AppData/Local/shyhurricane"),
])
def test_native_defaults(monkeypatch, tmp_path, platform, suffix):
    monkeypatch.setattr(Path, "is_dir", lambda path: False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(data_paths.sys, "platform", platform)
    monkeypatch.delenv("DATA_DIR")
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    root = tmp_path / suffix
    assert data_paths.resolve_data_dir() == root
    assert data_paths.resolve_data_dir("case-a") == root / "case-a"
    assert not root.exists()


def test_native_environment_overrides(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "is_dir", lambda path: False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(data_paths.sys, "platform", "linux")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert data_paths.default_data_dir() == tmp_path / "state/shyhurricane"
    monkeypatch.setenv("XDG_STATE_HOME", "relative")
    assert data_paths.default_data_dir() == tmp_path / ".local/state/shyhurricane"
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert data_paths.default_data_dir() == tmp_path / "local/shyhurricane"


def test_precedence_expansion_and_relative_resolution(monkeypatch, tmp_path):
    root = tmp_path / "default"
    monkeypatch.setattr(data_paths, "default_data_dir", lambda: root)
    monkeypatch.setenv("DATA_DIR", "environment")
    assert data_paths.resolve_data_dir() == root / "environment"
    assert data_paths.resolve_data_dir("cli") == root / "cli"
    monkeypatch.setenv("HOME", str(tmp_path))
    assert data_paths.resolve_data_dir("~/expanded") == tmp_path / "expanded"
    monkeypatch.chdir(tmp_path)
    assert data_paths.resolve_data_dir("cli") == root / "cli"


@pytest.mark.parametrize("value", ["", "  ", "../escape", "case/../../escape"])
def test_invalid_selections(monkeypatch, tmp_path, value):
    monkeypatch.setattr(data_paths, "default_data_dir", lambda: tmp_path / "default")
    with pytest.raises(ValueError):
        data_paths.resolve_data_dir(value)
    monkeypatch.setenv("DATA_DIR", value)
    with pytest.raises(ValueError):
        data_paths.resolve_data_dir()


def test_relative_symlink_escape_rejected(monkeypatch, tmp_path):
    root = tmp_path / "default"
    root.mkdir()
    (root / "outside").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(data_paths, "default_data_dir", lambda: root)
    with pytest.raises(ValueError, match="stay within"):
        data_paths.resolve_data_dir("outside/assessment")


def test_configure_propagates_absolute_root_to_spawned_process(monkeypatch, tmp_path):
    monkeypatch.setattr(data_paths, "default_data_dir", lambda: tmp_path)
    root = data_paths.configure_data_dir("assessment")
    assert root.is_dir()
    assert os.environ["DATA_DIR"] == str(root)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(target=child_paths, args=(queue,))
    process.start()
    try:
        assert queue.get(timeout=30) == (str(root), str(root / "queues/ingest_queue"))
    finally:
        process.join(timeout=30)
        if process.is_alive():
            process.kill()
            process.join()
        queue.close()
        queue.join_thread()
    assert process.exitcode == 0
    process.close()


def test_configure_rejects_file_and_unwritable_root(monkeypatch, tmp_path):
    file = tmp_path / "file"
    file.touch()
    with pytest.raises(FileExistsError):
        data_paths.configure_data_dir(file)

    def denied(*args, **kwargs):
        raise PermissionError("read-only")

    monkeypatch.setattr(Path, "mkdir", denied)
    with pytest.raises(PermissionError, match="read-only"):
        data_paths.configure_data_dir(tmp_path / "denied")


def test_all_local_stores_share_root_and_are_isolated(monkeypatch, tmp_path):
    roots = [tmp_path / name for name in ("one", "two")]
    for root in roots:
        data_paths.configure_data_dir(root)
        config = ServerConfig(data_dir=str(root))
        assert config.database == str(root / "qdrant")
        assert config.graph_database == str(root / "graph")
        assert get_state_path("remote:6333", "certs") == root / "certs"
        assert get_log_path("remote:6333", "index.jsonl") == root / "logs/index.jsonl"
        queue = get_persistent_queue("remote:6333", "ingest_queue")
        try:
            assert queue.path == str(root / "queues/ingest_queue")
            assert queue.total == 0
            queue.put({"root": str(root)})
        finally:
            queue.close()
        artifacts = ArtifactStore("remote:6333")
        try:
            assert artifacts.root == root / "graph_state"
        finally:
            artifacts.close()
        pages = ResultPageStore(str(data_paths.state_path("tool_cache")))
        assert pages.root == root / "tool_cache/result_pages"
    assert (roots[0] / "queues/ingest_queue/data.db").is_file()
    assert (roots[1] / "queues/ingest_queue/data.db").is_file()


@pytest.mark.parametrize("endpoint", ["host:6333", "127.0.0.1:1234", "[::1]:6333"])
def test_remote_qdrant(monkeypatch, endpoint):
    monkeypatch.setenv("QDRANT", endpoint)
    assert ServerConfig().database == endpoint


@pytest.mark.parametrize("endpoint", [
    "", "local/path", "/tmp/db", "host:0", "host:65536", "host:abc", "bad\thost:6333", "bad\nhost:6333",
])
def test_invalid_qdrant_override(monkeypatch, endpoint):
    monkeypatch.setenv("QDRANT", endpoint)
    with pytest.raises(ValueError, match="QDRANT"):
        data_paths.qdrant_location()


@pytest.mark.parametrize("endpoint", ["bolt://host:7687", "neo4j+s://host", "bolt+ssc://host"])
def test_remote_neo4j(monkeypatch, endpoint):
    monkeypatch.setenv("NEO4J", endpoint)
    assert ServerConfig().graph_database == endpoint


@pytest.mark.parametrize("endpoint", ["", "local/path", "/tmp/graph", "https://host"])
def test_invalid_neo4j_override(monkeypatch, endpoint):
    monkeypatch.setenv("NEO4J", endpoint)
    with pytest.raises(ValueError, match="NEO4J"):
        data_paths.neo4j_location()


def test_parser_accepts_only_new_storage_option():
    parser = argparse.ArgumentParser()
    data_paths.add_data_dir_argument(parser)
    assert parser.parse_args(["--data-dir", "case"]).data_dir == "case"
    assert parser.parse_args([]).data_dir is None
    for flag in ("--database", "--graph-database"):
        with pytest.raises(SystemExit):
            parser.parse_args([flag, "old"])


@pytest.mark.parametrize("command", ["backfill", "rebuild"])
def test_maintenance_cli_uses_shared_root(monkeypatch, tmp_path, capsys, command):
    from shyhurricane.graph import backfill, rebuild

    module = {"backfill": backfill, "rebuild": rebuild}[command]
    selected = tmp_path / "selected"
    monkeypatch.setattr(data_paths, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr("sys.argv", [command, "--data-dir", "selected"])
    calls = []

    def operation(db, **kwargs):
        calls.append((db, data_paths.resolve_data_dir()))
        return 0 if command == "backfill" else {"dry_run": True}

    monkeypatch.setattr(module, command, operation)
    module.main()
    assert calls == [(str(selected / "qdrant"), selected)]
    if command == "rebuild":
        assert json.loads(capsys.readouterr().out)["dry_run"]


@pytest.mark.parametrize("command", ["backfill", "rebuild"])
def test_maintenance_cli_reports_invalid_root(monkeypatch, command):
    from shyhurricane.graph import backfill, rebuild

    monkeypatch.setattr("sys.argv", [command, "--data-dir", ""])
    with pytest.raises(SystemExit) as error:
        {"backfill": backfill, "rebuild": rebuild}[command].main()
    assert error.value.code == 2
