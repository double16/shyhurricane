import json

import pytest
from haystack import Document

import shyhurricane.mcp_server.tools.findings as findings


async def noop(*args, **kwargs):
    return None


class Queue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class Store:
    def __init__(self, docs):
        self.docs = list(docs)
        self.filters = []

    async def filter_documents_async(self, filters):
        self.filters.append(filters)
        return self.docs


class ServerContext:
    def __init__(self, store=None):
        self.task_queue = Queue()
        self.stores = {"finding": store or Store([])}


def patch_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(findings, "get_server_context", get_fake_server_context)
    monkeypatch.setattr(findings, "log_tool_history", noop)


@pytest.mark.asyncio
async def test_save_finding_rejects_invalid_target(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await findings.save_finding(None, "not a target", "# finding", "Title")

    assert result.instructions == findings.finding_target_invalid_instructions
    assert ctx.task_queue.items == []


@pytest.mark.asyncio
async def test_save_finding_enqueues_valid_target(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await findings.save_finding(None, "https://example.com", "# finding", "Title")

    assert result.instructions == "Finding has been saved and can be retrieved later."
    assert ctx.task_queue.items[0].target == "https://example.com"
    assert ctx.task_queue.items[0].markdown == "# finding"
    assert ctx.task_queue.items[0].title == "Title"


def finding_doc(**meta):
    base = {"title": "Finding", "url": "https://example.com/a", "host": "example.com", "domain": "example.com"}
    base.update(meta)
    return Document(content="# body", meta=base)


@pytest.mark.asyncio
async def test_query_findings_by_url_and_limit(monkeypatch):
    store = Store([finding_doc(), finding_doc(url="https://example.com/b", title="Second")])
    patch_context(monkeypatch, ServerContext(store))

    result = await findings.query_findings(None, "https://example.com/a", limit=1)

    assert result.instructions == findings.finding_instructions
    assert result.limit == 10
    assert result.has_more is False
    assert [finding.title for finding in result.findings] == ["Finding", "Second"]
    assert store.filters[0]["conditions"][1]["field"] == "meta.url"


@pytest.mark.asyncio
async def test_query_findings_by_netloc_host_domain_and_invalid(monkeypatch):
    store = Store([])
    patch_context(monkeypatch, ServerContext(store))

    netloc = await findings.query_findings(None, "example.com:8443")
    host = await findings.query_findings(None, "api.example.com")
    domain = await findings.query_findings(None, "example.com")
    invalid = await findings.query_findings(None, "not a target")

    assert netloc.instructions == findings.finding_not_found_instructions
    assert host.instructions == findings.finding_not_found_instructions
    assert domain.instructions == findings.finding_not_found_instructions
    assert invalid.instructions == findings.finding_target_invalid_instructions
    assert [call["conditions"][1]["field"] for call in store.filters] == [
        "meta.netloc",
        "meta.host",
        "meta.host",
        "meta.domain",
    ]


class FakeRequest:
    def __init__(self, content_type, chunks=None, form_data=None):
        self.headers = {"Content-Type": content_type}
        self.chunks = chunks or []
        self.form_data = form_data or {}

    async def stream(self):
        for chunk in self.chunks:
            yield chunk

    async def form(self):
        return self.form_data


@pytest.mark.asyncio
async def test_save_finding_api_accepts_jsonl_and_form(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    json_request = FakeRequest(
        "application/json",
        [
            (json.dumps({"target": "https://example.com/a", "title": "A", "markdown": "# A"}) + "\n").encode(),
            (json.dumps({"targets": ["example.com"], "title": "B", "markdown": "# B"}) + "\n").encode(),
        ],
    )
    form_request = FakeRequest(
        "application/x-www-form-urlencoded",
        form_data={"targets": ["example.com"], "title": "C", "markdown": "# C"},
    )

    json_response = await findings.save_finding_api(json_request)
    form_response = await findings.save_finding_api(form_request)

    assert json_response.status_code == 201
    assert form_response.status_code == 201
    assert [item.title for item in ctx.task_queue.items] == ["A", "B", "C"]


@pytest.mark.asyncio
async def test_save_finding_api_rejects_bad_input(monkeypatch):
    patch_context(monkeypatch, ServerContext())

    assert (await findings.save_finding_api(FakeRequest("text/plain"))).status_code == 400
    assert (await findings.save_finding_api(FakeRequest("application/json", [b"{bad"]))).status_code == 400
    assert (await findings.save_finding_api(
        FakeRequest("application/json", [json.dumps({"target": "", "markdown": ""}).encode()])
    )).status_code == 400
