import json
import sys

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
        for doc in documents:
            doc.embedding = [1.0]
        return {"documents": documents}


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
