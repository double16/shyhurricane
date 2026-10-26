"""The parser supervisor bounds wall time and memory and always reaps child work."""

import io
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from shyhurricane.graph import parser_worker
from shyhurricane.graph.model import Projection, projection_snapshot


@pytest.mark.parametrize("failure", [
    None, "error", "missing", "memory", "time", "disappeared", "offline", "output", "malformed", "exit",
])
def test_parent_bounds_and_reaps_parser(tmp_path, event, monkeypatch, failure):
    capture = event()
    artifacts = SimpleNamespace(root=tmp_path, reference_epoch=1)
    if failure == "offline":
        artifacts.reference_epoch = 0
        artifacts.connection = MagicMock()
        artifacts.connection.execute.return_value.fetchone.return_value = (1,)

        def write(key, state):
            path = tmp_path / "snapshot.json"
            path.write_text(json.dumps(state))
            return path

        artifacts.write = write
    process = MagicMock(pid=123, returncode=-9 if failure == "exit" else 0)
    process.poll.side_effect = [None, 0, 0] if failure in {"memory", "time", "disappeared"} else [0, 0]
    monkeypatch.setattr(parser_worker, "MAX_RSS", 1 if failure == "memory" else 100)
    monkeypatch.setattr(parser_worker, "MAX_SECONDS", -1 if failure == "time" else 240)
    monkeypatch.setattr(parser_worker, "MAX_OUTPUT_BYTES", 1 if failure == "output" else 1024 * 1024)
    monitored = MagicMock()
    monitored.memory_info.return_value.rss = 2
    if failure == "disappeared":
        monitored.memory_info.side_effect = psutil.NoSuchProcess(123)
    monkeypatch.setattr(parser_worker.psutil, "Process", lambda pid: monitored)
    monkeypatch.setattr(parser_worker.time, "sleep", lambda value: None)

    def start(*args, **kwargs):
        request = json.load(kwargs["stdin"])
        assert (request["snapshot_path"] is not None) is (failure == "offline")
        if failure != "missing":
            from pathlib import Path

            Path(request["output"]).with_suffix(".tmp").write_text("interrupted output")

            Path(request["output"]).write_text("{" if failure == "malformed" else json.dumps(
                {"error": "bad input"} if failure == "error" else projection_snapshot(Projection(capture))
            ))
        return process

    monkeypatch.setattr(parser_worker.subprocess, "Popen", start)
    cleanup = MagicMock(side_effect=OSError("no Docker"))
    monkeypatch.setattr(parser_worker.subprocess, "run", cleanup)
    if failure in {"error", "missing", "memory", "time", "output", "malformed", "exit"}:
        with pytest.raises((ValueError, TimeoutError)):
            parser_worker.parse(capture, artifacts)
    else:
        assert parser_worker.parse(capture, artifacts).event == capture
    cleanup.assert_called_once()
    assert not list(tmp_path.glob("shyhurricane-parse-*.json"))
    assert not list(tmp_path.glob("shyhurricane-parse-*.tmp"))
    assert not (tmp_path / "snapshot.json").exists()


def test_timeout_escalates_termination_and_waits(tmp_path, event, monkeypatch):
    process = MagicMock(pid=123)
    process.poll.return_value = None
    process.wait.side_effect = [subprocess.TimeoutExpired("parser", 2), None]
    monkeypatch.setattr(parser_worker.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(parser_worker.subprocess, "run", MagicMock(side_effect=subprocess.TimeoutExpired("docker", 10)))
    monkeypatch.setattr(parser_worker, "MAX_SECONDS", -1)
    monkeypatch.setattr(parser_worker.psutil, "Process", lambda pid: SimpleNamespace(
        memory_info=lambda: SimpleNamespace(rss=0)))
    kill = MagicMock()
    monkeypatch.setattr(parser_worker.os, "killpg", kill)
    with pytest.raises(TimeoutError):
        parser_worker.parse(event(), SimpleNamespace(root=tmp_path, reference_epoch=1))
    assert kill.call_count == process.wait.call_count == 2


@pytest.mark.parametrize("failure", [False, True])
def test_child_writes_atomic_snapshot_or_explicit_error(tmp_path, event, monkeypatch, failure):
    capture = event()
    output = tmp_path / "out.json"
    request = {"event": capture, "root": str(tmp_path), "epoch": 1, "output": str(output),
               "document_contexts": [], "open_world": False}
    monkeypatch.setattr(parser_worker.sys, "stdin", io.StringIO(json.dumps(request)))
    artifacts = MagicMock()
    monkeypatch.setattr("shyhurricane.graph.epoch_catalog.SnapshotArtifacts", lambda *args: artifacts)

    def extract(*args, **kwargs):
        if failure:
            raise ValueError("invalid capture")
        return Projection(capture)

    monkeypatch.setattr("shyhurricane.graph.extract.extract", extract)
    monkeypatch.setattr(parser_worker.logging, "disable", lambda level: None)
    parser_worker.main()
    artifacts.close.assert_called_once()
    result = json.loads(output.read_text())
    assert ("error" in result) is failure
    if failure:
        assert result["diagnostic"]["stage"] == "extraction"
        assert result["diagnostic"]["type"] == "ValueError"
        assert "invalid capture" not in json.dumps(result)
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("body,mime", [
    ('<form id="f"><input name="x"></form><a href="/next">Next</a>', "text/html"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><a href="/next"/></svg>', "image/svg+xml"),
    ("plain response", "text/plain"),
    ("const x = location.hash; fetch(x)", "application/javascript"),
    ('//# sourceMappingURL=data:application/json,%7B%22version%22:3,%22sources%22:[%22a.js%22],'
     '%22sourcesContent%22:[%22fetch(location.hash)%22]%7D', "application/javascript"),
])
def test_real_subprocess_matches_direct_extraction(graph_paths, event, body, mime, tmp_path, monkeypatch):
    import os
    import shutil
    import sys
    from pathlib import Path

    from shyhurricane.graph.artifacts import ArtifactStore
    from shyhurricane.graph.extract import extract

    (tmp_path / "sitecustomize.py").write_text(
        "import sys\n"
        "class Guard:\n"
        " def find_spec(self, name, *args):\n"
        "  if name.split('.')[0] in {'torch', 'haystack'} or name.startswith('shyhurricane.task_queue'):\n"
        "   raise AssertionError('Heavyweight parser dependency: ' + name)\n"
        "sys.meta_path.insert(0, Guard())\n"
    )
    monkeypatch.setenv("PYTHONPATH", f"{tmp_path}{os.pathsep}{Path.cwd()}")
    shim = tmp_path / "docker"
    analyzer = Path("src/docker/unix_command/graph-analysis/analyze.cjs").resolve()
    shim.write_text(
        f"#!{sys.executable}\n"
        "import os,sys\n"
        "if sys.argv[1] == 'rm': sys.exit(0)\n"
        "if sys.argv[-1].endswith('jsdeobf.sh'):\n"
        " assert '--name' in sys.argv and '--network=none' in sys.argv and '--memory=3g' in sys.argv\n"
        " sys.stdout.write(sys.stdin.read()); sys.exit(0)\n"
        f"os.execv({shutil.which('node')!r}, ['node', {str(analyzer)!r}])\n"
    )
    shim.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event(body=body, mime=mime))
        isolated = projection_snapshot(parser_worker.parse(capture, artifacts))
        direct = projection_snapshot(extract(capture, artifacts))
        assert isolated == direct
        assert artifacts.connection.execute("SELECT count(*) FROM main.refs").fetchone()[0] >= 0
    finally:
        artifacts.close()


def test_parser_imports_do_not_load_indexing_models():
    import sys

    result = subprocess.run([
        sys.executable, "-c",
        "import sys; import shyhurricane.graph.epoch_catalog, shyhurricane.graph.extract, "
        "shyhurricane.javascript_deobfuscation; "
        "assert not any(m == 'torch' or m == 'haystack' or m.startswith('shyhurricane.task_queue') "
        "for m in sys.modules)",
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_child_initialization_error_retains_safe_traceback(tmp_path, event, monkeypatch):
    output = tmp_path / "out.json"
    request = {"event": event(), "root": str(tmp_path), "epoch": 1, "output": str(output)}
    monkeypatch.setattr(parser_worker.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(parser_worker.logging, "disable", lambda level: None)
    parser_worker.main()
    result = json.loads(output.read_text())
    assert result["diagnostic"]["stage"] == "initialization"
    assert result["diagnostic"]["type"] == "FileNotFoundError"
    assert result["diagnostic"]["traceback"]
    assert str(tmp_path) not in json.dumps(result)


def test_snapshot_reference_writes_target_main_table(graph_paths, event):
    from shyhurricane.graph.artifacts import ArtifactStore
    from shyhurricane.graph.epoch_catalog import SnapshotArtifacts

    artifacts = ArtifactStore("db")
    capture = artifacts.register(event())
    marker = artifacts.write("snapshot", {"epoch": 1, "watermark": 1, "policies": []})
    snapshot = SnapshotArtifacts(artifacts.root, marker)
    try:
        snapshot.references(capture["id"], ["https://example.com/app.js"])
        assert snapshot.connection.execute("SELECT * FROM main.refs").fetchall() == [
            ("https://example.com/app.js", capture["id"])
        ]
        assert snapshot.connection.execute("SELECT epoch_id FROM main.graph_reference_revisions").fetchone() == (1,)
    finally:
        snapshot.close()
        artifacts.close()


def test_launch_failure_removes_offline_marker(tmp_path, event, monkeypatch):
    artifacts = SimpleNamespace(root=tmp_path, reference_epoch=0, connection=MagicMock())
    artifacts.connection.execute.return_value.fetchone.return_value = (0,)
    marker = tmp_path / "marker.json"

    def write(*args):
        marker.write_text("{}")
        return marker

    artifacts.write = write
    monkeypatch.setattr(parser_worker.subprocess, "Popen", MagicMock(side_effect=OSError("unavailable")))
    with pytest.raises(OSError):
        parser_worker.parse(event(), artifacts)
    assert not marker.exists()
