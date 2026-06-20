import json

import pytest

import shyhurricane.mcp_server.tools.deobfuscate_javascript as deobf
import shyhurricane.mcp_server.tools.register_hostname_address as register
import shyhurricane.mcp_server.tools.status as status_tool


async def noop(*args, **kwargs):
    return None


class Queue:
    def __init__(self, active):
        self.active = active

    def active_size(self):
        return self.active


class Store:
    def __init__(self, count):
        self.count = count

    async def count_documents_async(self):
        return self.count


class Record:
    def __init__(self, meta):
        self.payload = {"meta": meta}


class StatusServerContext:
    db = "db"
    qdrant_client = object()
    stores = {"content": Store(2), "network": Store(3)}
    ingest_queue = Queue(4)
    proxy_host = "127.0.0.1"
    proxy_port = 8080
    proxy_ca_cert_path = None


async def get_status_server_context():
    return StatusServerContext()


async def fake_scroll(records):
    for record in records:
        yield record


@pytest.mark.asyncio
async def test_status_aggregates_counts_and_metadata(monkeypatch):
    records = [
        Record({"domain": "Example.com", "host": "WWW.Example.com"}),
        Record({"domain": "example.com", "host": "api.example.com"}),
        Record({"host": "api.example.com"}),
    ]
    monkeypatch.setattr(status_tool, "get_server_context", get_status_server_context)
    monkeypatch.setattr(status_tool, "get_doc_type_queue", lambda db: Queue(5))
    monkeypatch.setattr(status_tool, "scroll_qdrant_collection", lambda **kwargs: fake_scroll(records))

    response = await status_tool.status(None)
    body = json.loads(response.body)

    assert response.status_code == 200
    assert body["document_counts"] == {"content": 2, "network": 3}
    assert body["domain_counts"] == {"example.com": 2}
    assert body["host_counts"] == {"www.example.com": 1, "api.example.com": 2}
    assert body["index_active"] == 4
    assert body["type_specific_index_active"] == 5


@pytest.mark.asyncio
async def test_register_hostname_address_success_already_and_error(monkeypatch):
    calls = []
    hosts = {"known.test": "127.0.0.1"}

    def fake_get_additional_hosts(ctx, additional=None):
        if additional:
            calls.append(additional)
            hosts.update(additional)
        return hosts

    monkeypatch.setattr(register, "log_tool_history", noop)
    monkeypatch.setattr(register, "get_additional_hosts", fake_get_additional_hosts)

    assert await register.register_hostname_address(None, "known.test", "127.0.0.1") == (
        register.register_hostname_address_instructions_already_mapped
    )
    assert await register.register_hostname_address(None, "new.test", "127.0.0.2") == (
        register.register_hostname_address_instructions
    )
    assert calls == [{"new.test": "127.0.0.2"}]


@pytest.mark.asyncio
async def test_register_hostname_address_returns_error_when_mapping_rejected(monkeypatch):
    monkeypatch.setattr(register, "log_tool_history", noop)
    monkeypatch.setattr(register, "get_additional_hosts", lambda ctx, additional=None: {})

    assert await register.register_hostname_address(None, "bad host", "not-an-ip") == (
        register.register_hostname_address_instructions_error
    )


class CommandResult:
    def __init__(self, return_code, output):
        self.return_code = return_code
        self.output = output


@pytest.mark.asyncio
async def test_deobfuscate_javascript_handles_empty_failure_and_success(monkeypatch):
    monkeypatch.setattr(deobf, "log_tool_history", noop)

    assert await deobf.deobfuscate_javascript(None, "   ") == ""

    async def failed(*args, **kwargs):
        return CommandResult(1, "ignored")

    monkeypatch.setattr(deobf, "_run_unix_command", failed)
    assert await deobf.deobfuscate_javascript(None, "var a=1;") == "var a=1;"

    async def succeeded(*args, **kwargs):
        return CommandResult(0, "var readable = 1;")

    monkeypatch.setattr(deobf, "_run_unix_command", succeeded)
    assert await deobf.deobfuscate_javascript(None, "eval('x')") == "var readable = 1;"
