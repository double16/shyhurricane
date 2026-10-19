import json
from unittest.mock import AsyncMock

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


@pytest.mark.asyncio
async def test_status_aggregates_counts_and_metadata(monkeypatch):
    monkeypatch.setattr(status_tool, "get_server_context", get_status_server_context)
    monkeypatch.setattr(status_tool, "persistent_queue_counts", AsyncMock(return_value=queue_counts(4, 5)))

    async def domain_and_host_counts(*args, **kwargs):
        return {"example.com": 2}, {"www.example.com": 1, "api.example.com": 2}

    monkeypatch.setattr(status_tool, "get_domain_and_host_counts", domain_and_host_counts)

    response = await status_tool.status(None)
    body = json.loads(response.body)

    assert response.status_code == 200
    assert body["document_counts"] == {"content": 2, "network": 3}
    assert body["domain_counts"] == {"example.com": 2}
    assert body["host_counts"] == {"www.example.com": 1, "api.example.com": 2}
    assert body["queues"] == queue_counts(4, 5)
    assert "index_active" not in body
    assert "type_specific_index_active" not in body


@pytest.mark.asyncio
async def test_status_includes_proxy_ca_certificate(monkeypatch, tmp_path):
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text("test certificate")

    class CertServerContext(StatusServerContext):
        proxy_ca_cert_path = str(cert_path)

    async def get_cert_context():
        return CertServerContext()

    monkeypatch.setattr(status_tool, "get_server_context", get_cert_context)
    monkeypatch.setattr(status_tool, "persistent_queue_counts", AsyncMock(return_value=queue_counts(4, 0)))

    async def empty_domain_and_host_counts(*args):
        return {}, {}

    monkeypatch.setattr(status_tool, "get_domain_and_host_counts", empty_domain_and_host_counts)

    response = await status_tool.status(None)

    assert json.loads(response.body)["proxy_ca_cert"] == "test certificate"


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

    empty = await deobf.deobfuscate_javascript(None, "   ")
    assert empty.text == ""
    assert empty.transformation_status == "empty"

    async def failed(*args, **kwargs):
        return CommandResult(1, "ignored")

    monkeypatch.setattr(deobf, "_run_unix_command", failed)
    failure = await deobf.deobfuscate_javascript(None, "var a=1;")
    assert failure.text == "var a=1;"
    assert failure.transformation_status == "failed"
    assert await deobf.deobfuscate_javascript_full(None, "var a=1;") == "var a=1;"

    monkeypatch.setattr(deobf, "_run_unix_command", AsyncMock(return_value=None))
    assert (await deobf.deobfuscate_javascript(None, "var a=1;")).transformation_status == "failed"

    async def succeeded(*args, **kwargs):
        return CommandResult(0, "var readable = 1;")

    monkeypatch.setattr(deobf, "_run_unix_command", succeeded)
    success = await deobf.deobfuscate_javascript(None, "eval('x')")
    assert success.text == "var readable = 1;"
    assert success.transformation_status == "succeeded"
    assert await deobf.deobfuscate_javascript_full(None, "eval('x')") == "var readable = 1;"

    monkeypatch.setattr(deobf, "_run_unix_command", AsyncMock(return_value=CommandResult(0, "same")))
    assert (await deobf.deobfuscate_javascript(None, "same")).transformation_status == "succeeded"


def queue_counts(ingest, doc_type):
    return {name: {"pending": pending, "processing": 0, "failed": 0}
            for name, pending in (("ingest", ingest), ("type_specific_index", doc_type),
                                  ("scan_findings", 0), ("graph", 0))}


@pytest.mark.asyncio
@pytest.mark.parametrize("failed", [0, 3])
async def test_status_always_includes_queue_states(monkeypatch, failed):
    counts = queue_counts(0, 0)
    counts["scan_findings"]["failed"] = failed
    counts["graph"]["processing"] = 2
    monkeypatch.setattr(status_tool, "get_server_context", get_status_server_context)
    monkeypatch.setattr(status_tool, "persistent_queue_counts", AsyncMock(return_value=counts))
    monkeypatch.setattr(status_tool, "get_domain_and_host_counts", AsyncMock(return_value=({}, {})))
    response = await status_tool.status(None)
    assert json.loads(response.body)["queues"] == counts


@pytest.mark.asyncio
async def test_status_propagates_queue_read_error(monkeypatch):
    import sqlite3

    monkeypatch.setattr(status_tool, "get_server_context", get_status_server_context)
    monkeypatch.setattr(status_tool, "persistent_queue_counts", AsyncMock(side_effect=sqlite3.OperationalError("locked")))
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        await status_tool.status(None)


async def test_status_includes_cached_disk_snapshot(monkeypatch):
    from types import SimpleNamespace

    from shyhurricane.disk_space import DiskSpaceGuard
    from shyhurricane.server_config import ServerConfig

    guard = DiskSpaceGuard("/data", ServerConfig())
    context = StatusServerContext()
    context.health_monitor = SimpleNamespace(disk_guard=guard)
    monkeypatch.setattr(status_tool, "get_server_context", AsyncMock(return_value=context))
    monkeypatch.setattr(status_tool, "persistent_queue_counts", AsyncMock(return_value=queue_counts(4, 0)))
    monkeypatch.setattr(status_tool, "get_domain_and_host_counts", AsyncMock(return_value=({}, {})))
    monkeypatch.setattr("shyhurricane.disk_space.shutil.disk_usage", lambda path: pytest.fail("status probed disk"))
    response = await status_tool.status(None)
    assert json.loads(response.body)["disk"] == guard.snapshot()
