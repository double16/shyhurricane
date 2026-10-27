"""The benchmark verifies results without modifying its input corpus."""

import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def benchmark_module():
    path = Path(".github/scripts/benchmark-graph-storage.py")
    spec = importlib.util.spec_from_file_location("benchmark_graph_storage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("jsonl", [False, True])
def test_storage_benchmark_compares_formats_and_preserves_source(tmp_path, benchmark_module, jsonl):
    corpus = tmp_path / "corpus"
    values = [{"response_body": "<p>same response</p>" * 1000, "index": index} for index in range(12)]
    if jsonl:
        corpus.write_text("\n".join(json.dumps(value) for value in values))
    else:
        corpus.mkdir()
        for index, value in enumerate(values):
            (corpus / f"{index}.json").write_text(json.dumps(value))
        (corpus / "oversized.json").write_text('"' + "a" * 2_000_000 + '"')
    output = tmp_path / "result.json"
    result = benchmark_module.benchmark(corpus, output, max_files=13, max_bytes=1_000_000)
    assert result == json.loads(output.read_text())
    assert result["sample_files"] == 12
    modes = {row["mode"]: row for row in result["results"]}
    assert modes["production"]["allocated_bytes"] < modes["json_files"]["allocated_bytes"]
    assert modes["sqlite_zstd_level1"]["payload_bytes"] < modes["sqlite_raw"]["payload_bytes"]
    assert all(row["read_p95_ms"] >= 0 and row["peak_python_bytes"] > 0 for row in modes.values())
    assert corpus.is_file() if jsonl else len(list(corpus.glob("*.json"))) == 13


def test_benchmark_limits_empty_corpus_and_cli(tmp_path, benchmark_module, monkeypatch):
    with pytest.raises(ValueError, match="Corpus"):
        benchmark_module.benchmark(tmp_path, tmp_path / "out")
    path = tmp_path / "data.jsonl"
    path.write_text("\n{}\n{}\n")
    assert benchmark_module.benchmark(path, tmp_path / "result", max_files=2)["sample_files"] == 2
    with pytest.raises(ValueError):
        benchmark_module.benchmark(path, tmp_path / "result", max_bytes=1)
    monkeypatch.setattr("sys.argv", ["benchmark", "--corpus", str(path), "--output", str(tmp_path / "cli")])
    benchmark_module.main()
    assert (tmp_path / "cli").exists()
    monkeypatch.setattr("sys.argv", ["benchmark", "--corpus", str(path), "--output", "unused", "--max-files", "0"])
    with pytest.raises(SystemExit):
        benchmark_module.main()
