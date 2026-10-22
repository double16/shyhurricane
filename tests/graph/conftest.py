import json
import subprocess
from pathlib import Path

import pytest

from shyhurricane.graph.model import capture_event


@pytest.fixture
def graph_paths(monkeypatch, tmp_path):
    def path(db, name):
        return tmp_path / name

    monkeypatch.setattr("shyhurricane.persistent_queue.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.graph.artifacts.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.graph.status.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.indexing_wait.persistent_queue_path", path)
    return tmp_path


@pytest.fixture
def event():
    def create(url="https://example.com/page", body="", mime="text/html", **kwargs):
        return capture_event(
            {
                "url": url,
                "method": "GET",
                "timestamp": "2026-01-01T00:00:00Z",
                "request_headers": {},
                "response_headers": {"Content-Type": mime},
                "response_code": 200,
                "response_body": body,
                "request_body": None,
                **kwargs,
            }
        )

    return create


@pytest.fixture
def javascript_runner():
    """Run the shipped AST analyzer without Docker or target network access."""
    analyzer = Path("src/docker/unix_command/graph-analysis/analyze.cjs").resolve()

    def run(source, filename):
        result = subprocess.run(
            ["node", str(analyzer)], input=json.dumps({"source": source, "filename": filename}),
            text=True, capture_output=True, check=True, timeout=15,
        )
        return json.loads(result.stdout)

    return run
