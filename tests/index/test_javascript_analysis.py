import json
import io
import tarfile
from types import SimpleNamespace

from haystack import Document

from shyhurricane.index import javascript_analysis as analysis


class Queue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class Store:
    def __init__(self, content=None):
        self.content = content
        self.filters = []

    def filter_documents(self, filters):
        self.filters.append(filters)
        if self.content is None:
            return []
        return [Document(content=self.content)]


def document(url="https://example.com/app.js", content="eval(input)", content_type="text/javascript"):
    return Document(content=content, meta={"url": url, "content_type": content_type,
                                           "request_headers": json.dumps({"Cookie": "session=x"})})


def result(path="/work/scan/source.js"):
    return {"results": [{"check_id": "javascript.security.eval", "path": path,
                         "start": {"line": 4}, "extra": {"message": "Dangerous eval",
                                                        "severity": "WARNING", "lines": "eval(input)"}}]}


def test_js_without_map_scans_and_saves_finding(monkeypatch):
    queue = Queue()
    store = Store()
    calls = []
    monkeypatch.setattr(analysis, "_run_opengrep", lambda source, source_map: calls.append((source, source_map))
                        or result())
    monkeypatch.setattr(analysis, "_fetch_map", lambda *args: (_ for _ in ()).throw(AssertionError("network")))

    assert analysis.analyze_document(document(), False, store, queue) == 1
    assert calls == [("eval(input)", None)]
    assert queue.items[0].target == "https://example.com/app.js"
    assert "Dangerous eval" in queue.items[0].markdown
    assert queue.items[0].finding_id


def test_js_url_with_plain_text_mime_is_scanned(monkeypatch):
    queue = Queue()
    monkeypatch.setattr(analysis, "_run_opengrep", lambda source, source_map: result())
    assert analysis.analyze_document(document(content_type="text/plain"), False, Store(), queue) == 1


def test_cached_map_is_preferred_over_javascript(monkeypatch):
    source_map = json.dumps({"version": 3, "sources": ["src/app.js"], "sourcesContent": ["eval(input)"]})
    store = Store(source_map)
    queue = Queue()
    calls = []
    monkeypatch.setattr(analysis, "_run_opengrep", lambda source, map_content: calls.append(map_content)
                        or result("/work/scan/work/src/app.js"))

    assert analysis.analyze_document(document(), False, store, queue) == 1
    assert calls == [source_map]
    assert "src/app.js" in queue.items[0].markdown
    assert store.filters[0]["value"] == "https://example.com/app.js.map"


def test_open_world_fetches_map_and_invalid_map_falls_back(monkeypatch):
    queue = Queue()
    calls = []
    monkeypatch.setattr(analysis, "_fetch_map", lambda url, headers: calls.append((url, headers)) or "broken")
    monkeypatch.setattr(analysis, "_run_opengrep", lambda source, source_map: result() if source_map is None else None)

    assert analysis.analyze_document(document(), True, Store(), queue) == 1
    assert calls == [("https://example.com/app.js.map", {"Cookie": "session=x"})]


def test_indexed_map_scans_original_source(monkeypatch):
    source_map = json.dumps({"version": 3, "sources": ["original.js"], "sourcesContent": ["eval(x)"]})
    calls = []
    monkeypatch.setattr(analysis, "_run_opengrep", lambda source, map_content: calls.append((source, map_content))
                        or result("/work/scan/original.js"))
    queue = Queue()

    assert analysis.analyze_document(document(url="https://example.com/app.js.map", content=source_map,
                                              content_type="application/json"), False, Store(), queue) == 1
    assert calls == [("", source_map)]
    assert queue.items[0].target == "https://example.com/app.js"


def test_unsupported_and_oversized_documents_are_skipped(monkeypatch):
    monkeypatch.setattr(analysis, "_run_opengrep", lambda *args: (_ for _ in ()).throw(AssertionError("scan")))
    assert analysis.analyze_document(document(url="https://example.com/a.css", content_type="text/css"),
                                     True, Store(), Queue()) == 0
    assert analysis.analyze_document(document(content="a" * (analysis.MAX_JAVASCRIPT_BYTES + 1)),
                                     True, Store(), Queue()) == 0


def test_source_map_url_preserves_query_and_requires_javascript():
    assert analysis.source_map_url("https://example.com/app.js?v=1") == "https://example.com/app.js.map?v=1"
    assert analysis.source_map_url("https://example.com/app.css") is None
    assert analysis.javascript_url_from_map("https://example.com/app.js.map?v=1") == \
        "https://example.com/app.js?v=1"
    assert analysis.javascript_url_from_map("https://example.com/a.map") is None


def test_fetch_map_limits_response_and_forwards_selected_headers(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        def __init__(self, chunks):
            self.chunks = chunks

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_bytes(self):
            yield from self.chunks

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"timeout": 5, "follow_redirects": False}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def stream(self, method, url, headers):
            calls.append((method, url, headers))
            return Response([b"{\"version\":3}"])

    monkeypatch.setattr(analysis.httpx, "Client", Client)
    assert analysis._fetch_map("https://example.com/a.js.map", {"Cookie": "x", "Host": "bad"}) == \
        '{"version":3}'
    assert calls == [("GET", "https://example.com/a.js.map", {"Cookie": "x"})]

    class OversizedClient(Client):
        def stream(self, method, url, headers):
            return Response([b"a" * (analysis.MAX_SOURCE_MAP_BYTES + 1)])

    monkeypatch.setattr(analysis.httpx, "Client", OversizedClient)
    assert analysis._fetch_map("https://example.com/a.js.map", {}) is None

    class NotFoundClient(Client):
        def stream(self, method, url, headers):
            response = Response([])
            response.status_code = 404
            return response

    monkeypatch.setattr(analysis.httpx, "Client", NotFoundClient)
    assert analysis._fetch_map("https://example.com/a.js.map", {}) is None


def test_fetch_map_handles_network_failure(monkeypatch):
    class BrokenClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            raise analysis.httpx.ReadError("failed")

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(analysis.httpx, "Client", BrokenClient)
    assert analysis._fetch_map("https://example.com/a.js.map", {}) is None


def test_cached_map_skips_missing_and_oversized_content():
    assert analysis._cached_map(None, "https://example.com/a.js.map") is None
    assert analysis._cached_map(Store("a" * (analysis.MAX_SOURCE_MAP_BYTES + 1)),
                                "https://example.com/a.js.map") is None


def test_cached_map_selects_newest_eligible_document():
    class MultiStore:
        def __init__(self, docs):
            self.docs = docs

        def filter_documents(self, filters):
            assert filters == {"field": "meta.url", "operator": "==", "value": "https://example.com/a.js.map"}
            return self.docs

    docs = [
        Document(content="newer", meta={"timestamp_float": 20.0}),
        Document(content="oldest", meta={"timestamp_float": 10.0}),
        Document(content="x" * (analysis.MAX_SOURCE_MAP_BYTES + 1), meta={"timestamp_float": 50.0}),
        Document(content="", meta={"timestamp_float": 40.0}),
        Document(content="without timestamp", meta={}),
    ]
    assert analysis._cached_map(MultiStore(docs), "https://example.com/a.js.map") == "newer"
    assert analysis._cached_map(MultiStore([docs[2], docs[3]]), "https://example.com/a.js.map") is None
    assert analysis._cached_map(MultiStore([docs[4], docs[1]]), "https://example.com/a.js.map") == "oldest"


def test_scan_process_parses_json_and_handles_failure(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(result()).encode(), stderr=b"")

    monkeypatch.setattr(analysis.subprocess, "run", run)
    assert analysis._run_opengrep("eval(input)", None) == result()
    assert calls[0][-1] == "/usr/local/bin/scan_javascript.sh"
    assert "-i" in calls[0]

    monkeypatch.setattr(analysis.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout=b"", stderr=b"failure"))
    assert analysis._run_opengrep("eval(input)", None) is None

    monkeypatch.setattr(analysis.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=b"bad json", stderr=b""))
    assert analysis._run_opengrep("eval(input)", None) is None

    def timeout(*args, **kwargs):
        raise analysis.subprocess.TimeoutExpired("docker", 240)

    monkeypatch.setattr(analysis.subprocess, "run", timeout)
    assert analysis._run_opengrep("eval(input)", None) is None


def test_scan_process_writes_map(monkeypatch):
    def run(command, **kwargs):
        with tarfile.open(fileobj=io.BytesIO(kwargs["input"])) as archive:
            assert archive.extractfile("source.js.map").read() == b'{"version":3}'
        return SimpleNamespace(returncode=0, stdout=b'{"results":[]}', stderr=b"")

    monkeypatch.setattr(analysis.subprocess, "run", run)
    assert analysis._run_opengrep("", '{"version":3}') == {"results": []}


def test_finding_rejects_incomplete_match_and_uses_stable_id():
    assert analysis._finding("https://example.com/a.js", {}, False) is None
    first = analysis._finding("https://example.com/a.js", result()["results"][0], False)
    second = analysis._finding("https://example.com/a.js", result()["results"][0], False)
    assert first.finding_id == second.finding_id


def test_unusable_map_or_scan_result_produces_no_finding(monkeypatch):
    queue = Queue()
    monkeypatch.setattr(analysis, "_run_opengrep", lambda *args: None)
    assert analysis.analyze_document(document(), False, Store(), queue) == 0
    bad_map = document(url="https://example.com/a.js.map", content="bad", content_type="application/json")
    assert analysis.analyze_document(bad_map, False, Store(), queue) == 0

    monkeypatch.setattr(analysis, "_run_opengrep", lambda *args: {"results": [{}, result()["results"][0]]})
    assert analysis.analyze_document(document(), False, Store(), queue) == 1
