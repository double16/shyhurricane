import json
from dataclasses import replace

from haystack import Document

from shyhurricane.task_queue.finding_worker import FindingContext, save_finding_worker
from shyhurricane.task_queue.types import SaveFindingQueueItem


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

    def write_documents(self, documents, policy):
        self.written.append((documents, policy))


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
    ctx.stores = {"finding": Store()}
    ctx.embedders = {"finding": Embedder()}
    ctx.splitters = {"finding": Splitter()}
    ctx.doc_type_queue = DocTypeQueue()
    ctx.gen_title = title_generator or TitleGenerator()
    ctx.finding_log_path = str(tmp_path / "findings.jsonl")
    return ctx


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
    assert ctx.doc_type_queue.items == [written_doc]


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
