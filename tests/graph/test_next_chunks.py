import json
from unittest.mock import MagicMock

import httpx
import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.index import next_chunks
from shyhurricane.index.input_documents import IngestableRequestResponse


def task(url="https://example.com/_next/static/chunks/item.js"):
    return json.dumps({next_chunks.TASK: {"url": url, "declaring_capture": "capture"}})


@pytest.fixture
def artifacts(graph_paths):
    store = ArtifactStore("db")
    yield store
    store.close()


def response_client(monkeypatch, *, status=200, body=b"export default 1", error=None):
    client = MagicMock()
    client.__enter__.return_value = client
    response = MagicMock(status_code=status, headers={"content-type": "application/javascript"})
    response.iter_bytes.return_value = [body]
    stream = MagicMock()
    stream.__enter__.return_value = response
    if error:
        stream.__enter__.side_effect = error
    client.stream.return_value = stream
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(next_chunks.httpx, "Client", factory)
    return factory


def test_fetch_open_world_and_closed_world(artifacts, monkeypatch):
    factory = response_client(monkeypatch)
    assert next_chunks.fetch_task(task(), open_world=False, artifacts=artifacts) is None
    factory.assert_not_called()
    exchange = json.loads(next_chunks.fetch_task(task(), open_world=True, artifacts=artifacts))
    assert exchange["response"]["body"] == "export default 1"
    assert exchange["request"]["headers"] == {}
    assert factory.call_args.kwargs == {"timeout": 5, "follow_redirects": False, "verify": False}
    original = '{"request": {}}'
    assert next_chunks.fetch_task(original, open_world=True, artifacts=artifacts) == original


@pytest.mark.parametrize("url", [
    "file:///tmp/chunk.js", "https://user:password@example.com/_next/static/chunks/a.js",
    "https://example.com/other.js", "https://example.com/_next/static/chunks/a.css",
])
def test_invalid_task_url(artifacts, monkeypatch, url):
    factory = response_client(monkeypatch)
    assert next_chunks.fetch_task(task(url), open_world=True, artifacts=artifacts) is None
    factory.assert_not_called()


@pytest.mark.parametrize("status,body,error", [
    (302, b"", None), (404, b"", None), (200, b"12345", None),
    (200, b"\xff", None), (200, b"", httpx.ConnectError("unavailable")),
])
def test_fetch_failures(artifacts, monkeypatch, status, body, error):
    response_client(monkeypatch, status=status, body=body, error=error)
    monkeypatch.setattr(next_chunks, "MAX_BYTES", 4)
    assert next_chunks.fetch_task(task(), open_world=True, artifacts=artifacts) is None


def test_existing_capture_reused(artifacts, event, monkeypatch):
    factory = response_client(monkeypatch)
    artifacts.register(event(url="https://example.com/_next/static/chunks/item.js", body="code"))
    assert next_chunks.fetch_task(task(), open_world=True, artifacts=artifacts) is None
    factory.assert_not_called()


def test_schedule_deduplicates_and_ignores_other_assets(artifacts, event):
    queue = MagicMock()
    rr = IngestableRequestResponse(**{
        **event(body='1:I[42,["static/chunks/item.js"],"default"]\n', mime="text/x-component")["data"],
        "response_rtt": None, "technologies": None, "forms": None,
    })
    next_chunks.schedule(artifacts, queue, rr)
    next_chunks.schedule(artifacts, queue, rr)
    assert queue.put.call_count == 1
    assert json.loads(queue.put.call_args.args[0])[next_chunks.TASK]["url"].endswith("/item.js")
    rr.response_headers = {"content-type": "application/json"}
    next_chunks.schedule(artifacts, queue, rr)
    rr.response_headers = {"content-type": "text/html"}
    rr.response_body = ""
    next_chunks.schedule(artifacts, queue, rr)
    assert queue.put.call_count == 1


def test_schedule_pages_manifest(artifacts, event, monkeypatch):
    monkeypatch.setattr(next_chunks, "run_javascript", lambda *_: {
        "next_manifest_chunks": [["/items", "static/chunks/item.js"]],
    })
    rr = IngestableRequestResponse(**{
        **event(url="https://example.com/_next/static/build/_buildManifest.js",
                body="self.__BUILD_MANIFEST = {}", mime="application/javascript")["data"],
        "response_rtt": None, "technologies": None, "forms": None,
    })
    queue = MagicMock()
    next_chunks.schedule(artifacts, queue, rr)
    assert queue.put.call_count == 1


def test_capture_tap_schedules_then_ingests_fetched_response(artifacts, event, monkeypatch):
    from shyhurricane.graph.ingest import CaptureGraphEvents
    from shyhurricane.graph.model import capture_event
    from shyhurricane.index.input_documents import KatanaDocument
    from shyhurricane.persistent_queue import get_ingest_queue

    rr = IngestableRequestResponse(**{
        **event(body='1:I[42,["static/chunks/item.js"],"default"]\n', mime="text/x-component")["data"],
        "response_rtt": None, "technologies": None, "forms": None,
    })
    monkeypatch.setattr("shyhurricane.server_config.get_server_config", lambda: MagicMock(open_world=True))
    CaptureGraphEvents("db").run([rr])
    queue = get_ingest_queue("db")
    item = queue.get(block=False)
    response_client(monkeypatch)
    fetched = next_chunks.fetch_task(item, open_world=True, artifacts=artifacts)
    parsed = KatanaDocument().run(fetched)["request_responses"][0]
    assert json.loads(parsed.to_katana())["capture_provenance"] == parsed.capture_provenance
    assert parsed.capture_provenance["declaring_capture"] == capture_event(rr)["id"]
    assert "capture_provenance" not in rr.model_dump()
    graph = next_chunks.extract(capture_event(parsed), javascript_runner=lambda *_: {})
    page = graph.nodes[graph.resource(parsed.url)]
    assert page["capture_source"] == "next_manifest_fetch"
    assert page["declaring_capture_id"] == capture_event(rr)["id"]
    queue.ack(item)
    queue.close()


def test_capture_tap_closed_world_schedules_nothing(artifacts, event, monkeypatch):
    from shyhurricane.graph.ingest import CaptureGraphEvents
    from shyhurricane.persistent_queue import get_ingest_queue

    rr = IngestableRequestResponse(**{
        **event(body='1:I[42,["static/chunks/item.js"],"default"]\n', mime="text/x-component")["data"],
        "response_rtt": None, "technologies": None, "forms": None,
    })
    monkeypatch.setattr("shyhurricane.server_config.get_server_config", lambda: MagicMock(open_world=False))
    CaptureGraphEvents("db").run([rr])
    queue = get_ingest_queue("db")
    assert queue.size == 0
    queue.close()


def test_older_response_does_not_suppress_new_manifest(artifacts, event, monkeypatch):
    artifacts.register(event(url="https://example.com/_next/static/chunks/item.js", body="old"))
    factory = response_client(monkeypatch)
    pending = json.loads(task())
    pending[next_chunks.TASK]["observed_at"] = 9999999999
    assert next_chunks.fetch_task(json.dumps(pending), open_world=True, artifacts=artifacts)
    factory.assert_called_once()


def test_manifest_parser_failure_keeps_original_ingestion_available(artifacts, event, monkeypatch):
    monkeypatch.setattr(next_chunks, "extract", MagicMock(side_effect=ValueError("unsupported")))
    response = IngestableRequestResponse(**{
        **event(body="<html/>")["data"], "response_rtt": None, "technologies": None, "forms": None,
    })
    queue = MagicMock()
    next_chunks.schedule(artifacts, queue, response)
    queue.put.assert_not_called()
