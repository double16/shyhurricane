"""Stage diagnostics and supervised normalization preserve bounded fallback behavior."""

import json
import subprocess
import time
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.parser_diagnostics import measured, remaining_seconds
from shyhurricane.javascript_deobfuscation import deobfuscate_javascript


def test_stage_records_and_deadline(tmp_path, monkeypatch):
    monkeypatch.delenv("_SHYHURRICANE_PARSE_DEADLINE", raising=False)
    monkeypatch.delenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", raising=False)
    assert remaining_seconds() == 240
    assert measured("noop")(lambda: 3)() == 3
    path = tmp_path / "stages"
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DIAGNOSTICS", str(path))
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DEADLINE", str(time.monotonic() - 1))
    assert remaining_seconds() == 0.001
    with pytest.raises(ValueError):
        measured("example")(lambda: int("invalid"))()
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["state"] for row in records] == ["started", "finished"]
    assert all(row["stage"] == "example" for row in records)


@pytest.mark.parametrize("outcome", ["success", "empty", "failed", "timeout"])
def test_supervised_normalization(monkeypatch, outcome):
    monkeypatch.setenv("_SHYHURRICANE_PARSE_DEADLINE", str(time.monotonic() + 100))
    monkeypatch.setenv("_SHYHURRICANE_PARSE_CONTAINER", "isolated-test")
    process = MagicMock(returncode=1 if outcome == "failed" else 0)
    process.communicate.return_value = ("" if outcome == "empty" else "normalized", None)
    if outcome == "timeout":
        process.communicate.side_effect = [subprocess.TimeoutExpired("normalizer", 50), ("", None)]
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.subprocess.Popen", lambda *a, **kw: process)
    cleanup = MagicMock()
    monkeypatch.setattr("shyhurricane.javascript_deobfuscation.subprocess.run", cleanup)
    if outcome == "timeout":
        with pytest.raises(TimeoutError):
            deobfuscate_javascript("source")
        process.kill.assert_called_once()
        cleanup.assert_called_once()
    else:
        assert deobfuscate_javascript("source") == ("normalized" if outcome == "success" else "source")
    assert 0 < process.communicate.call_args_list[0].kwargs["timeout"] <= 50
