import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import Mock

import httpx
import pytest
from haystack import Document
from qdrant_client.http.exceptions import ResponseHandlingException

import shyhurricane.task_queue.finding_worker as finding_worker
from shyhurricane.task_queue.finding_worker import FindingContext, save_finding_worker
from shyhurricane.task_queue.types import SaveFindingQueueItem


@pytest.fixture(autouse=True)
def correlation_handoff(monkeypatch):
    monkeypatch.setattr(finding_worker, "submit_document", Mock())


class Embedder:
    def __init__(self):
        self.warmed = False

    def warm_up(self):
        self.warmed = True

    def run(self, documents):
        return {"documents": [replace(doc, embedding=[1.0, 2.0]) for doc in documents]}


class Splitter:
    def run(self, documents):
        return {"documents": documents}


class Store:
    def __init__(self):
        self.written = []
        self.documents = {}

    def filter_documents(self, filters):
        return [doc for doc in self.documents.values()
                if doc.meta.get("finding_fingerprint") == filters["value"]]

    def write_documents(self, documents, policy):
        self.written.append((documents, policy))
        self.documents.update({doc.id: doc for doc in documents})


class DocTypeQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class TitleGenerator:
    def run(self, documents):
        doc = documents[0]
        doc.meta["title"] = "Generated"
        return {"documents": [doc]}


def make_context(tmp_path, title_generator=None):
    ctx = object.__new__(FindingContext)
    ctx.db = "test"
    ctx.stores = {"finding": Store()}
    ctx.embedders = {"finding": Embedder()}
    ctx.splitters = {"finding": Splitter()}
    ctx.doc_type_queue = DocTypeQueue()
    ctx.gen_title = title_generator or TitleGenerator()
    ctx.finding_log_path = str(tmp_path / "findings.jsonl")
    ctx.lock_path = tmp_path / "save.lock"
    return ctx


def test_qdrant_write_failure_propagates_before_downstream_queueing(tmp_path):
    ctx = make_context(tmp_path)
    failure = ResponseHandlingException(httpx.ReadTimeout("write timeout"))
    ctx.stores["finding"].write_documents = Mock(side_effect=failure)
    item = SaveFindingQueueItem("https://example.com/", "finding", "Title", "stable-id")
    with pytest.raises(ResponseHandlingException) as raised:
        save_finding_worker(ctx, item)
    assert raised.value is failure
    assert ctx.doc_type_queue.items == []
    ctx.stores["finding"].write_documents.assert_called_once()


def test_finding_context_warm_up_calls_embedders(tmp_path):
    ctx = make_context(tmp_path)

    ctx.warm_up()

    assert ctx.embedders["finding"].warmed is True


def test_save_finding_worker_writes_log_document_store_and_doc_type_queue(tmp_path):
    ctx = make_context(tmp_path)
    item = SaveFindingQueueItem("https://example.com/path", "# markdown", "Explicit title")

    save_finding_worker(ctx, item)

    logged = json.loads((tmp_path / "findings.jsonl").read_text().strip())
    assert logged == {"target": "https://example.com/path", "title": "Explicit title", "markdown": "# markdown"}
    written_doc: Document = ctx.stores["finding"].written[0][0][0]
    assert written_doc.content == "# markdown"
    assert written_doc.meta["url"] == "https://example.com/path"
    assert written_doc.meta["host"] == "example.com"
    assert written_doc.meta["content_type"] == "text/x-finding"
    assert written_doc.meta["title"] == "Explicit title"
    assert written_doc.embedding == [1.0, 2.0]
    assert ctx.doc_type_queue.items == [replace(
        written_doc, meta={key: value for key, value in written_doc.meta.items() if key != "finding_handoff_pending"},
    )]
    assert ctx.stores["finding"].documents[written_doc.id].meta["finding_handoff_pending"] is False


def test_save_finding_worker_uses_scan_finding_id(tmp_path):
    ctx = make_context(tmp_path)
    save_finding_worker(ctx, SaveFindingQueueItem("https://example.com/app.js", "# finding", "Scan", "stable-id"))
    assert ctx.stores["finding"].written[0][0][0].id == "stable-id"


def test_save_finding_worker_generates_title_and_disables_bad_log_path(tmp_path):
    bad_path = tmp_path / "missing" / "findings.jsonl"
    ctx = make_context(tmp_path)
    ctx.finding_log_path = str(bad_path)
    item = SaveFindingQueueItem("example.com", "# markdown", None)

    save_finding_worker(ctx, item)

    written_doc = ctx.stores["finding"].written[0][0][0]
    assert written_doc.meta["title"] == "Generated"
    assert ctx.finding_log_path is None


def test_save_finding_worker_ignores_invalid_target(tmp_path):
    ctx = make_context(tmp_path)

    save_finding_worker(ctx, SaveFindingQueueItem("not a target", "# markdown", "Title"))

    assert ctx.stores["finding"].written == []
    assert ctx.doc_type_queue.items == []


def test_save_finding_worker_skips_disabled_log(tmp_path):
    ctx = make_context(tmp_path)
    ctx.finding_log_path = None

    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "# markdown", "Title"))

    assert ctx.stores["finding"].written
    assert not (tmp_path / "findings.jsonl").exists()


@pytest.mark.parametrize("timestamp", ["202601020304", None])
def test_finding_context_uses_run_timestamp(monkeypatch, tmp_path, timestamp):
    monkeypatch.setattr(finding_worker, "build_stores", lambda *args: {"finding": Store()})
    monkeypatch.setattr(finding_worker, "build_embedders", lambda **kwargs: {"finding": Embedder()})
    monkeypatch.setattr(finding_worker, "build_splitters", lambda *args: {"finding": Splitter()})
    monkeypatch.setattr(finding_worker, "GenerateTitleAndDescription", lambda *args: TitleGenerator())
    monkeypatch.setattr(finding_worker, "get_log_path", lambda db, name: tmp_path / name)
    monkeypatch.setattr(finding_worker, "get_state_path", lambda db, name: tmp_path)
    monkeypatch.setattr(finding_worker, "get_log_timestamp", lambda: "202612312359")

    ctx = FindingContext("db", object(), object(), DocTypeQueue(), log_timestamp=timestamp)
    expected = timestamp or "202612312359"
    assert ctx.finding_log_path.name == f"finding-{expected}.jsonl"
    assert not ctx.finding_log_path.exists()
    for title in ["First", "Second"]:
        save_finding_worker(ctx, SaveFindingQueueItem("example.com", "# finding", title))
    assert [json.loads(line)["title"] for line in ctx.finding_log_path.read_text().splitlines()] == ["First"]


@pytest.mark.parametrize("target,port,scheme,suffixes", [
    ("https://api.example.com/App.JS?q=.html", 443, "https", ["api.example.com", "example.com", "com"]),
    ("http://example.com/a", 80, "http", ["example.com", "com"]),
    ("https://example.com:8443/a", 8443, "https", ["example.com", "com"]),
    ("example.com:8080", 8080, "", ["example.com", "com"]),
    ("example.com", 0, "", ["example.com", "com"]),
    ("[2001:db8::1]:8080", 8080, "", ["2001:db8::1"]),
])
def test_saved_finding_search_metadata(tmp_path, target, port, scheme, suffixes):
    ctx = make_context(tmp_path)
    save_finding_worker(ctx, SaveFindingQueueItem(target, "# finding", "Title"))
    meta = ctx.stores["finding"].written[0][0][0].meta
    assert meta["version"] == finding_worker.FINDING_VERSION == 3
    assert meta["port"] == port
    assert meta["search_scheme"] == scheme
    assert meta["search_host_suffixes"] == suffixes
    assert meta["search_extension"] == ("js" if "App.JS" in target else "")
    assert bool(meta["search_url_trigrams"]) == bool(scheme)


def test_warm_up_without_embedder_hook(tmp_path):
    ctx = make_context(tmp_path)
    ctx.embedders["finding"] = object()
    ctx.warm_up()


def test_duplicate_keeps_first_content_title_timestamp_and_skips_processing(tmp_path):
    ctx = make_context(tmp_path)
    ctx.embedders["finding"].run = Mock(wraps=ctx.embedders["finding"].run)
    ctx.gen_title.run = Mock(wraps=ctx.gen_title.run)
    save_finding_worker(ctx, SaveFindingQueueItem("https://EXAMPLE.com:443", " # finding\r\n", None))
    original = next(iter(ctx.stores["finding"].documents.values()))
    for title in [None, "Changed title"]:
        save_finding_worker(ctx, SaveFindingQueueItem("https://example.com/", "# finding", title))
    assert list(ctx.stores["finding"].documents.values()) == [original]
    assert len(ctx.stores["finding"].written) == 2  # Initial save and completed handoff marker.
    assert len(ctx.doc_type_queue.items) == 1
    assert len((tmp_path / "findings.jsonl").read_text().splitlines()) == 1
    ctx.gen_title.run.assert_called_once()
    ctx.embedders["finding"].run.assert_called_once()


def test_duplicate_across_scanner_and_manual_sources(tmp_path):
    ctx = make_context(tmp_path)
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Scanner", "scanner-id"))
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Manual"))
    assert list(ctx.stores["finding"].documents) == ["scanner-id"]
    assert len(ctx.doc_type_queue.items) == 1


def test_new_finding_and_changed_scanner_content(tmp_path):
    ctx = make_context(tmp_path)
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Manual"))
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "new evidence", "Manual"))
    save_finding_worker(ctx, SaveFindingQueueItem("other.example.com", "body", "Manual"))
    assert len(ctx.stores["finding"].documents) == 3
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "scan", "Scan", "scanner-id"))
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "updated scan", "Scan", "scanner-id"))
    assert ctx.stores["finding"].documents["scanner-id"].content == "updated scan"


def test_concurrent_submissions_and_recreated_context(tmp_path):
    ctx = make_context(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: save_finding_worker(
            ctx, SaveFindingQueueItem("example.com", "body", "Title"),
        ), range(12)))
    replacement = make_context(tmp_path)
    replacement.stores = ctx.stores
    save_finding_worker(replacement, SaveFindingQueueItem("example.com", "body", "Replacement"))
    assert len(ctx.stores["finding"].written) == 2
    assert len(ctx.doc_type_queue.items) == 1
    assert replacement.doc_type_queue.items == []


def test_lookup_failure_propagates_without_processing(tmp_path):
    ctx = make_context(tmp_path)
    ctx.stores["finding"].filter_documents = Mock(side_effect=RuntimeError("lookup failed"))
    with pytest.raises(RuntimeError, match="lookup failed"):
        save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Title"))
    assert ctx.stores["finding"].written == []
    assert ctx.doc_type_queue.items == []
    assert not (tmp_path / "findings.jsonl").exists()


@pytest.mark.parametrize("failure_stage", ["initial_write", "handoff", "completion_write"])
def test_retry_recovers_partial_save_without_reembedding_stored_document(tmp_path, failure_stage):
    ctx = make_context(tmp_path)
    store = ctx.stores["finding"]
    original_write = store.write_documents
    original_put = ctx.doc_type_queue.put
    ctx.embedders["finding"].run = Mock(wraps=ctx.embedders["finding"].run)
    item = SaveFindingQueueItem("example.com", "body", "First")

    def write(documents, policy):
        if failure_stage == "initial_write" or (
            failure_stage == "completion_write" and not documents[0].meta["finding_handoff_pending"]
        ):
            raise RuntimeError("write failed")
        original_write(documents, policy)

    store.write_documents = write
    if failure_stage == "handoff":
        ctx.doc_type_queue.put = Mock(side_effect=RuntimeError("queue failed"))
    with pytest.raises(RuntimeError):
        save_finding_worker(ctx, item)
    saved = list(store.documents.values())
    store.write_documents = original_write
    ctx.doc_type_queue.put = original_put
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Replacement"))
    completed = next(iter(store.documents.values()))
    assert completed.meta["finding_handoff_pending"] is False
    assert ctx.embedders["finding"].run.call_count == (2 if failure_stage == "initial_write" else 1)
    if saved:
        assert completed.meta["timestamp"] == saved[0].meta["timestamp"]
        assert completed.meta["title"] == "First"
    assert len(ctx.doc_type_queue.items) == (2 if failure_stage == "completion_write" else 1)
    assert all("finding_handoff_pending" not in doc.meta for doc in ctx.doc_type_queue.items)
    if failure_stage == "completion_write":
        assert ctx.doc_type_queue.items[0] == ctx.doc_type_queue.items[1]


def test_preexisting_record_without_fingerprint_does_not_prevent_new_save(tmp_path):
    ctx = make_context(tmp_path)
    legacy = Document(id="old", content="body", meta={"host": "example.com"})
    ctx.stores["finding"].documents[legacy.id] = legacy
    save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Title"))
    assert len(ctx.stores["finding"].documents) == 2


def test_real_qdrant_preserves_vector_and_filters_fingerprint_on_retry(tmp_path):
    from haystack_integrations.document_stores.qdrant import QdrantDocumentStore

    ctx = make_context(tmp_path)
    store = QdrantDocumentStore(location=":memory:", index="finding", embedding_dim=2, return_embedding=True)
    ctx.stores["finding"] = store
    original_put = ctx.doc_type_queue.put
    ctx.doc_type_queue.put = Mock(side_effect=RuntimeError("queue failed"))
    try:
        with pytest.raises(RuntimeError, match="queue failed"):
            save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "First"))
        original_vector = store.filter_documents()[0].embedding
        ctx.doc_type_queue.put = original_put
        save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Second"))
        save_finding_worker(ctx, SaveFindingQueueItem("example.com", "body", "Third"))
        assert store.count_documents() == 1
        assert store.filter_documents()[0].embedding == pytest.approx(original_vector)
        assert store.filter_documents()[0].meta["title"] == "First"
        assert len(ctx.doc_type_queue.items) == 1
    finally:
        store.close()


@pytest.mark.asyncio
async def test_mcp_http_and_scanner_submissions_share_deduplication(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from starlette.requests import Request

    import shyhurricane.mcp_server.tools.findings as tools
    from shyhurricane.index.javascript_analysis import _finding

    ctx = make_context(tmp_path)
    tasks = DocTypeQueue()

    async def get_context():
        return SimpleNamespace(db="test")

    async def log_history(*args, **kwargs):
        pass

    monkeypatch.setattr(tools, "get_server_context", get_context)
    monkeypatch.setattr(tools, "log_tool_history", log_history)
    monkeypatch.setattr(tools, "enqueue_finding", lambda db, item: tasks.put(item))
    scanner_item = _finding("https://example.com/app.js", {
        "check_id": "example-rule", "path": "/work/scan/app.js", "start": {"line": 1},
        "extra": {"message": "Example issue", "lines": "eval(input)"},
    }, False)
    tasks.put(scanner_item)
    result = await tools.save_finding(None, scanner_item.target, scanner_item.markdown, "Manual title")
    assert "queued" in result.instructions

    async def receive():
        return {"type": "http.request", "body": json.dumps({
            "target": scanner_item.target, "markdown": scanner_item.markdown, "title": "HTTP title",
        }).encode(), "more_body": False}

    request = Request({"type": "http", "headers": [(b"content-type", b"application/json")]}, receive)
    assert (await tools.save_finding_api(request)).status_code == 201
    assert len(tasks.items) == 3
    for item in tasks.items:
        save_finding_worker(ctx, item)
    assert len(ctx.stores["finding"].documents) == 1
    assert next(iter(ctx.stores["finding"].documents)) == scanner_item.finding_id
    assert len(ctx.doc_type_queue.items) == 1


def test_metadata_enrichment_is_durable_and_preserves_identity(tmp_path):
    ctx = make_context(tmp_path)
    first = SaveFindingQueueItem("https://example.com/app.js", "# issue", "Original", metadata={"severity": "high"})
    save_finding_worker(ctx, first)
    original = next(iter(ctx.stores["finding"].documents.values()))
    save_finding_worker(ctx, SaveFindingQueueItem(first.target, first.markdown, "Changed", metadata={
        "severity": "critical", "affected_method": "get", "parameter": {"name": "q"},
    }))
    enriched = ctx.stores["finding"].documents[original.id]
    assert enriched.meta["title"] == "Original"
    assert enriched.meta["timestamp"] == original.meta["timestamp"]
    assert enriched.meta["finding_metadata"] == {"severity": "high", "affected_method": "GET", "parameter": {"name": "q"}}
    assert enriched.meta["finding_metadata_conflicts"] == [
        {"field": "severity", "retained": "high", "submitted": "critical"}]
    assert finding_worker.submit_document.call_count == 2
    assert finding_worker.submit_document.call_args.args[1].id == original.id
    assert len(ctx.doc_type_queue.items) == 2
    # A retry carrying the same conflict does not enqueue duplicate work.
    save_finding_worker(ctx, SaveFindingQueueItem(first.target, first.markdown, "Changed", metadata={"severity": "critical"}))
    assert finding_worker.submit_document.call_count == 2


def test_failed_correlation_handoff_is_retried_before_acknowledgement(tmp_path):
    ctx = make_context(tmp_path)
    item = SaveFindingQueueItem("example.com", "finding", "Title", metadata={"source": "burp"})
    finding_worker.submit_document.side_effect = RuntimeError("unavailable")
    with pytest.raises(RuntimeError):
        save_finding_worker(ctx, item)
    doc = next(iter(ctx.stores["finding"].documents.values()))
    assert doc.meta["finding_handoff_pending"]
    assert not ctx.doc_type_queue.items
    finding_worker.submit_document.side_effect = None
    save_finding_worker(ctx, item)
    assert not ctx.stores["finding"].documents[doc.id].meta["finding_handoff_pending"]
    assert len(ctx.doc_type_queue.items) == 1
