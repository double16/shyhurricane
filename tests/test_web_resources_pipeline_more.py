import json
import sys
from collections import defaultdict
from dataclasses import replace

from haystack import Document

from shyhurricane.index.input_documents import IngestableRequestResponse
from shyhurricane.index import web_resources_pipeline as wrp


class Embedder:
    def __init__(self, batch_size=1):
        self.documents = []
        self.warmed = False
        self.batch_size = batch_size

    def warm_up(self):
        self.warmed = True

    def to_dict(self):
        return {"batch_size": self.batch_size}

    def run(self, documents):
        self.documents.extend(documents)
        return {"documents": [replace(doc, embedding=[1.0]) for doc in documents]}


class Store:
    def __init__(self, existing=None, exc=None):
        self.existing = existing or []
        self.exc = exc
        self.written = []
        self.filters = []

    def filter_documents(self, filters):
        self.filters.append(filters)
        return self.existing

    def write_documents(self, documents, policy=None):
        if self.exc:
            raise self.exc
        self.written.extend(documents)


class Pipe:
    def __init__(self):
        self.components = {}
        self.connections = []

    def add_component(self, name, component):
        self.components[name] = component

    def connect(self, left, right):
        self.connections.append((left, right))


def request_response(**overrides):
    values = {
        "url": "https://example.com:443/index.html",
        "timestamp": "2025-08-06T12:03:55.711-05:00",
        "method": "GET",
        "request_headers": {"Accept": "text/html"},
        "request_body": None,
        "response_code": 200,
        "response_headers": {"Content-Type": "text/html", "Etag": "abc"},
        "response_body": "<html><head><title>Home</title><meta name='description' content='Desc'></head><body><form action='/login' method='post'></form></body></html>",
        "response_rtt": 0.2,
        "technologies": ["nginx"],
        "forms": [{"method": "POST", "action": "/login"}],
    }
    values.update(overrides)
    return IngestableRequestResponse(**values)


def test_binary_detection_cache_helpers_and_normalization_cache_key():
    assert wrp.is_binary("abc", "text/plain") is False
    assert wrp.is_binary(None, "application/pdf") is True
    assert wrp.is_binary("<svg/>", "image/svg+xml") is False
    assert wrp.is_binary("é" * 200, "application/custom") is True
    assert wrp._quantize_timestamp("2025-08-06T12:03:55") == "2025-08-06T"
    assert wrp._cache_key_response_headers({"ETag": "abc", "X-Test": "no", "Cookie": "sid=1"}) == "abc,sid=1"


def test_request_response_to_document_creates_content_network_and_form_docs():
    embedder = Embedder()
    sparse = Embedder()
    converter = wrp.RequestResponseToDocument({"default": embedder, "content": embedder, "network": embedder,
                                               "forms": embedder}, sparse)

    result = converter.run([request_response()])
    docs = result["documents"]

    assert {doc.meta["type"] for doc in docs} == {"content", "network", "forms"}
    content = next(doc for doc in docs if doc.meta["type"] == "content")
    network = next(doc for doc in docs if doc.meta["type"] == "network")
    assert content.meta["host"] == "example.com"
    assert content.meta["domain"] == "example.com"
    assert content.meta["title"] == "Home"
    assert content.meta["description"] == "Desc"
    assert content.meta["response_rtt"] == 0.2
    assert "--- HTTP Request Headers ---" in network.content
    assert len(embedder.documents) == 3
    assert len(sparse.documents) == 3


def test_request_response_to_document_skips_bad_url_and_binary_content():
    converter = wrp.RequestResponseToDocument({"default": Embedder(), "network": Embedder()}, Embedder())

    assert converter.run([request_response(url="not a url")])["documents"] == []
    docs = converter.run([request_response(response_headers={"Content-Type": "application/pdf"},
                                           response_body="%PDF",
                                           forms=None)])["documents"]

    assert [doc.meta["type"] for doc in docs] == ["network"]


def test_normalize_documents_uses_cached_js_and_updates_length(monkeypatch):
    cached = Store([Document(content="function readable() {}", meta={})])
    cleaner = object()
    doc = Document(
        content="eval('x')",
        meta={
            "type": "content",
            "content_type": "application/javascript",
            "content_sha256": "sha",
            "response_headers": json.dumps({"Content-Length": "9"}),
        },
    )
    monkeypatch.setattr(wrp, "_deobfuscate_javascript", lambda content: "should-not-run")

    result = wrp.NormalizeDocuments(cleaner, {"content": cached}).run([doc])["documents"][0]

    assert result.content == "function readable() {}"
    assert result.meta["normalized"] is True
    assert json.loads(result.meta["response_headers"])["Content-Length"] == str(len(result.content))


def test_normalize_documents_handles_html_json_css_and_cleaner(monkeypatch):
    class Cleaner:
        def run(self, documents):
            return {"documents": [Document(content="cleaned text")]}

    monkeypatch.setattr(wrp, "normalize_html", lambda content: "html")
    monkeypatch.setattr(wrp, "normalize_json", lambda content: "json")
    monkeypatch.setattr(wrp, "normalize_css", lambda content: "css")
    docs = [
        Document(content="<b>x</b>", meta={"type": "content", "content_type": "text/html",
                                           "response_headers": "{}"}),
        Document(content='{"x":1}', meta={"type": "content", "content_type": "application/json",
                                          "response_headers": "{}"}),
        Document(content="body{}", meta={"type": "content", "content_type": "text/css",
                                         "response_headers": "{}"}),
        Document(content="plain", meta={"type": "content", "content_type": "text/plain",
                                        "response_headers": "{}"}),
        Document(content="skip", meta={"type": "network", "content_type": "text/plain"}),
    ]

    result = wrp.NormalizeDocuments(Cleaner(), {"content": Store()}).run(docs)["documents"]

    assert [doc.content for doc in result] == ["html", "json", "css", "cleaned text", "skip"]
    assert all(doc.meta.get("normalized") for doc in result[:4])


def test_filter_existing_documents_by_id_and_doc_type():
    missing_type = Document(content="x", id="missing", meta={})
    no_id = Document(content="x", meta={"type": "content"})
    existing = Document(content="x", id="existing", meta={"type": "content"})
    new = Document(content="x", id="new", meta={"type": "content"})

    by_id = wrp.FilterExistingDocumentsById({"content": Store([existing])})
    assert by_id.run([missing_type, no_id, existing, new])["documents"] == [missing_type]

    doc = Document(content="x", id="doc", meta={
        "url": "https://example.com/",
        "content_type": "text/html",
        "timestamp": "2025-08-06T",
        "content_sha256": "sha",
    })
    missing = Document(content="x", id="missing", meta={"url": "", "content_type": "", "timestamp": ""})
    assert wrp.FilterExistingDocumentsByDocType({"html": Store()}).run([doc, missing])["documents"] == [doc]
    assert wrp.FilterExistingDocumentsByDocType({"html": Store([doc])}).run([doc])["documents"] == []


def test_ingest_multi_store_writes_by_collection_and_keeps_documents():
    html_store = Store()
    network_store = Store(exc=RuntimeError("fail"))
    docs = [
        Document(content="html", id="h", meta={"type": "html", "token_length": sys.maxsize}),
        Document(content="net", id="n", meta={"type": "network", "token_length": sys.maxsize}),
        Document(content="unknown", id="u", meta={"type": "unknown", "token_length": sys.maxsize}),
    ]

    result = wrp.IngestMultiStore({"html": html_store, "network": network_store}).run(docs)

    assert result["documents"] == docs
    assert html_store.written == [docs[0]]


def test_generate_title_and_description_skips_uses_cache_and_parses_generator():
    class Generator:
        def __init__(self):
            self.calls = 0

        def run(self, prompt):
            self.calls += 1
            return {"replies": ['{"title": "Generated title", "description": "Generated desc"}']}

    class Config:
        def __init__(self):
            self.generator = Generator()

        def create_generator(self):
            return self.generator

    config = Config()
    component = wrp.GenerateTitleAndDescription(config)
    first = Document(content="body", meta={"status_code": 200, "type": "content", "url": "https://example.com"})
    cached = Document(content="body", meta={"status_code": 200, "type": "content", "url": "https://example.com"})
    skipped = Document(content="body", meta={"status_code": 404, "type": "content"})
    network = Document(content="body", meta={"status_code": 200, "type": "network"})

    component.run([first, cached, skipped, network])

    assert first.meta["title"] == "Generated title"
    assert cached.meta["description"] == "Generated desc"
    assert "title" not in skipped.meta
    assert "title" not in network.meta
    assert config.generator.calls == 1


def test_deobfuscate_javascript_empty_success_and_failure(monkeypatch):
    assert wrp._deobfuscate_javascript("") == ""

    class Stream:
        def __init__(self, lines):
            self.lines = list(lines)
            self.written = ""
            self.closed = False

        def write(self, value):
            self.written += value

        def close(self):
            self.closed = True

        def readline(self):
            if not self.lines:
                return ""
            return self.lines.pop(0)

    class Proc:
        def __init__(self, return_code, lines):
            self.return_code = return_code
            self.stdin = Stream([])
            self.stdout = Stream(lines)
            self.polls = 0

        def poll(self):
            self.polls += 1
            if self.polls == 1:
                return None
            return self.return_code

        def wait(self):
            return self.return_code

    procs = [Proc(0, ["readable\n"]), Proc(1, [""])]
    monkeypatch.setattr(wrp.subprocess, "Popen", lambda *args, **kwargs: procs.pop(0))
    monkeypatch.setattr(wrp, "unix_command_image", lambda: "image")

    assert wrp._deobfuscate_javascript("eval(1)") == "readable\n"
    assert wrp._deobfuscate_javascript("eval(2)") == "eval(2)"


def test_build_splitters_uses_token_lengths_and_suffix_splitter(monkeypatch):
    created = []

    class Splitter:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.warmed = False
            created.append(self)

        def warm_up(self):
            self.warmed = True

    monkeypatch.setattr(wrp, "SuffixIdSplitter", Splitter)

    splitters = wrp.build_splitters({"html": object(), "network": object()})

    assert set(splitters)
    assert all(splitter.warmed for splitter in splitters.values())
    assert all(splitter.kwargs["split_by"] == "word" for splitter in created)


def test_suffix_id_splitter_sets_child_ids_and_serializes_overlap(monkeypatch):
    splitter = object.__new__(wrp.SuffixIdSplitter)
    parent = Document(content="hello", id="parent", meta={})
    children = [
        Document(content="a", meta={"_split_overlap": {"doc_id": "old"}}),
        Document(content="b", meta={"_split_overlap": "ok"}),
    ]
    monkeypatch.setattr(wrp.DocumentSplitter, "_split_document", lambda self, doc: children)

    result = splitter._split_document(parent)

    assert [doc.id for doc in result] == ["parent_0", "parent_1"]
    assert result[0].meta["_split_overlap"] == '{"doc_id": "old"}'
    assert result[1].meta["_split_overlap"] == "ok"


def test_index_doc_type_documents_splits_embeds_and_stores(monkeypatch):
    html_embedder = Embedder(batch_size=2)
    sparse = Embedder()

    class Splitter:
        def run(self, documents):
            return {"documents": [
                Document(content=documents[0].content + "-1", id="s1", meta=documents[0].meta.copy()),
                Document(content=documents[0].content + "-2", id="s2", meta=documents[0].meta.copy()),
            ]}

    class MultiStore:
        def __init__(self):
            self.batches = []

        def run(self, documents):
            self.batches.append(list(documents))

    multi_store = MultiStore()
    component = wrp.IndexDocTypeDocuments({"default": html_embedder, "html": html_embedder}, sparse, multi_store)
    component.splitters = defaultdict(Splitter)
    doc = Document(content="<html></html>", meta={
        "url": "https://example.com/",
        "content_type": "text/html",
        "timestamp": "2025-08-06T12:03:55",
        "response_headers": "{}",
        "type": "content",
    })
    object.__setattr__(doc, "content", b"<html></html>")

    assert component.run([doc]) == {}

    assert set(d.content for d in html_embedder.documents) == {"<html></html>-1", "<html></html>-2"}
    assert len(html_embedder.documents) >= 2
    assert len(sparse.documents) == len(html_embedder.documents)
    assert len(multi_store.batches) >= 1
    assert {d.meta["type"] for d in multi_store.batches[0]} == {"html"}


def test_index_doc_type_documents_warm_up_and_skip_branches(monkeypatch):
    sparse = Embedder()
    multi_store = type("MultiStore", (), {"run": lambda self, documents: None})()
    component = wrp.IndexDocTypeDocuments({"default": Embedder(), "html": Embedder()}, sparse, multi_store)
    monkeypatch.setattr(wrp, "build_splitters", lambda embedders: {"html": object()})

    component.warm_up()
    component.warm_up()
    component.run([
        Document(content="", meta={"type": "content"}),
        Document(content="body", meta={"url": "", "content_type": "text/html", "timestamp": ""}),
        Document(content="body", meta={"url": "https://example.com/", "content_type": "application/pdf",
                                       "timestamp": "2025-08-06T", "response_headers": "{}"}),
    ])

    assert component.splitters == {"html": component.splitters["html"]}
    assert sparse.warmed is True


def test_build_stores_embedders_and_pipelines_are_wired(monkeypatch):
    stores = {}

    class DocumentStore:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.counted = False

        def count_documents(self):
            self.counted = True
            return 0

    class Cache:
        def __init__(self, config):
            self.config = config

        def get(self, doc_type_model):
            return f"embedder-{doc_type_model.doc_type}"

    class Config:
        def __init__(self):
            self.sparse_calls = 0

        def create_sparse_document_embedder(self, model):
            self.sparse_calls += 1
            return "sparse"

        def create_generator(self):
            return type("Generator", (), {"run": lambda self, prompt: {"replies": ["{}"]}})()

    def create_store(**kwargs):
        store = DocumentStore(**kwargs)
        stores[kwargs["index"]] = store
        return store

    monkeypatch.setattr(wrp, "create_qdrant_document_store", create_store)
    monkeypatch.setattr(wrp, "EmbedderCache", Cache)
    monkeypatch.setattr(wrp, "Pipeline", Pipe)
    monkeypatch.setattr(wrp, "ConditionalRouter", lambda **kwargs: ("router", kwargs))
    monkeypatch.setattr(wrp, "ListJoiner", lambda *args, **kwargs: ("joiner", args, kwargs))

    selected_stores = wrp.build_stores("db", doc_types={"content"})
    embedders = wrp.build_embedders(Cache("cfg"), doc_types={"content", "network"})
    ingest = wrp.build_ingest_pipeline("db", Config())
    doc_type = wrp.build_doc_type_pipeline("db", Config())
    cleaner = wrp.new_doc_cleaner()

    assert selected_stores
    assert all(store.counted for store in selected_stores.values())
    assert set(embedders) == {"content", "network"}
    assert {"input_router", "katana_document", "raw_document", "har_document", "output"}.issubset(ingest.components)
    assert ("normalize_document", "output") in ingest.connections
    assert {"input", "gen_title", "gen_doc_type"} == set(doc_type.components)
    assert cleaner.keep_id is True


def test_generate_title_and_description_ignores_invalid_generator_json():
    class Config:
        def create_generator(self):
            return type("Generator", (), {"run": lambda self, prompt: {"replies": ["not-json"]}})()

    doc = Document(content="body", meta={"status_code": 200, "type": "content"})

    result = wrp.GenerateTitleAndDescription(Config()).run([doc])["documents"][0]

    assert "title" not in result.meta
