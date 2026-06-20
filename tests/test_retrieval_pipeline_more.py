import builtins

from haystack import Document
from haystack.dataclasses import ChatMessage

from shyhurricane import retrieval_pipeline as rp


def test_query_clamps_defaults_and_filters_targets():
    result = rp.Query().run("find xss", max_results=5000, targets=["", "example.com"], filters=None)

    assert result["text"] == "find xss"
    assert result["max_results"] == 1000
    assert result["targets"] == ["example.com"]
    assert result["filters"] == {}
    assert result["doc_types"] == []


def test_combine_docs_sorts_and_boosts_requested_doc_types():
    docs = [
        Document(content="a", meta={"type": "network", "timestamp_float": 2}, score=0.6),
        Document(content="b", meta={"type": "content", "timestamp_float": 1}, score=0.2),
        Document(content="c", meta={"type": "content", "timestamp_float": 3}, score=0.1),
    ]

    result = rp.CombineDocs(["content", "network"]).run(doc_types=["content"], content=docs[:2], network=docs[2:])

    assert [doc.content for doc in result["documents"]] == ["b", "c", "a"]
    assert [doc.score for doc in result["documents"]] == [2.0, 1.0, 0.6]
    assert [doc.score for doc in docs] == [0.6, 0.2, 0.1]


def test_trace_docs_writes_debug_markdown(tmp_path):
    file = tmp_path / "trace.md"

    rp.TraceDocs(file).run(
        query="q",
        expanded_queries=["q1", "q2"],
        documents=[Document(content="body" * 400, meta={"url": "https://example.com"}, score=0.5)],
    )

    text = file.read_text()
    assert "# Q: q" in text
    assert "- q1" in text
    assert "https://example.com" in text
    assert "Score: 0.5" in text


def test_vuln_type_parser_accepts_json_iterables_and_ignores_invalid():
    result = rp.VulnTypeParser().run(['["SQL Injection", "XSS"]', '{"bad": "object"}', "not-json"])

    assert result["vuln_types"] == {"sql_injection", "xss", "bad"}


def make_expander(pipeline):
    expander = object.__new__(rp.QueryExpander)
    expander.query_expansion_prompt = "prompt"
    expander.doc_type = "nl"
    expander.number = 3
    expander.include_original_query = True
    expander.pipeline = pipeline
    expander.target_placeholders = rp.QueryExpander.target_placeholders
    return expander


class ExpanderPipeline:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def run(self, data):
        self.calls.append(data)
        return {"llm": {"replies": [self.replies.pop(0) if self.replies else ""]}}


def test_query_expander_splits_static_llm_results_and_applies_targets(monkeypatch):
    files = {
        "xss_nl.txt": "----\nstatic {NETLOC}\n----\nstatic two\n",
    }
    pipeline = ExpanderPipeline(["----\nllm example.com\n----\nllm two\n"])
    expander = make_expander(pipeline)

    monkeypatch.setattr(rp.os.path, "exists", lambda path: path.endswith("xss_nl.txt"))

    def fake_open(path, *args, **kwargs):
        return builtins.open(__file__, *args, **kwargs) if not path.endswith("xss_nl.txt") else _StringFile(
            files["xss_nl.txt"])

    monkeypatch.setattr(rp, "open", fake_open, raising=False)

    result = expander.run("original", targets=["target.test"], vuln_types=["xss"])

    assert result["queries"][0] == "original"
    assert "static target.test" in result["queries"]
    assert "llm target.test" in result["queries"]
    assert len(pipeline.calls) >= 1


class _StringFile:
    def __init__(self, text):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return self.text


class Warmable:
    def __init__(self, key, values=None, exc=None):
        self.key = key
        self.values = list(values or [])
        self.exc = exc
        self.warmed = False

    def warm_up(self):
        self.warmed = True

    def run(self, query):
        if self.exc:
            raise self.exc
        return {self.key: self.values.pop(0) if self.values else query}


class Retriever:
    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        docs = [
            Document(content="a", id="same", meta={"url": "https://example.com/a", "timestamp_float": 1}, score=0.4),
            Document(content="b", id="same", meta={"url": "https://example.com/a", "timestamp_float": 2}, score=0.9),
            Document(content="c", id="other", meta={"url": "https://example.com/c", "timestamp_float": 3}, score=0.2),
        ]
        return {"documents": docs}


def test_multi_query_retriever_warms_deduplicates_and_reports_progress():
    embedder = Warmable("embedding", [[1], [2]])
    sparse = Warmable("sparse_embedding", ["s1", "s2"])
    retriever = Retriever()
    messages = []
    component = rp.MultiQueryChromaRetriever("content", embedder, sparse, retriever)

    component.warm_up()
    result = component.run(["q1", "q2"], top_k=5000, filters={"field": "value"}, progress_callback=messages.append)

    assert embedder.warmed is True
    assert sparse.warmed is True
    assert len(result["documents"]) == 2
    assert [call["top_k"] for call in retriever.calls] == [1000, 1000]
    assert messages == ["Querying content: q1", "Querying content: q2"]


def test_chat_message_helpers_filter_merge_and_wrap(caplog):
    system = [ChatMessage.from_system("system")]
    memories = [ChatMessage.from_user("memory")]
    query = [ChatMessage.from_user("query")]

    merged = rp.ChatPromptTemplateBuilder(system).run(memories, query)["messages"]
    filtered = rp.ChatMessageFilter().run(merged + [ChatMessage.from_assistant("")])["messages"]
    wrapped = rp.ChatMessageToListAdapter().run(query[0])["values"]

    rp.ChatMessageLogger("label").run(filtered)
    rp.ChatMessageLogger("label").run([])

    assert merged == system + memories + query
    assert filtered == merged + [ChatMessage.from_assistant("")]
    assert wrapped == [query[0]]


def test_query_expander_number_one_and_retriever_error_path():
    expander = make_expander(ExpanderPipeline([]))
    expander.number = 1

    assert expander.run("original", targets=["example.com"], vuln_types=["xss"]) == {"queries": ["original"]}

    component = rp.MultiQueryChromaRetriever(
        "content",
        Warmable("embedding", exc=RuntimeError("embed failed")),
        Warmable("sparse_embedding"),
        Retriever(),
    )

    assert component.run(["q"], top_k=0)["documents"] == []


def test_build_document_and_website_context_pipelines_are_wired(monkeypatch):
    class Pipe:
        def __init__(self):
            self.components = {}
            self.connections = []

        def add_component(self, name, component):
            self.components[name] = component

        def connect(self, left, right):
            self.connections.append((left, right))

    class Config:
        def __init__(self):
            self.created_text = []

        def create_generator(self, **kwargs):
            return ("generator", kwargs)

        def create_sparse_text_embedder(self, model):
            return "sparse"

        def create_text_embedder(self, model):
            self.created_text.append(model)
            return Warmable("embedding")

    class Store:
        pass

    monkeypatch.setattr(rp, "Pipeline", Pipe)
    monkeypatch.setattr(rp, "QdrantHybridRetriever", lambda document_store: ("retriever", document_store))
    monkeypatch.setattr(rp, "create_qdrant_document_store", lambda **kwargs: Store())
    monkeypatch.setattr(rp, "QueryExpander", lambda *args, **kwargs: ("expander", kwargs))

    import asyncio

    pipe, retrievers, stores = asyncio.run(rp.build_document_pipeline("db", Config()))
    website = rp.build_website_context_pipeline(Config())

    assert {"combine", "query", "vuln_type_prompt", "vuln_type_llm", "vuln_type_parser", "query_expander"}.issubset(
        pipe.components)
    assert retrievers
    assert stores
    assert any(left == "query.max_results" and right.endswith(".top_k") for left, right in pipe.connections)
    assert {"builder", "llm"} == set(website.components)
    assert ("builder", "llm") in website.connections
