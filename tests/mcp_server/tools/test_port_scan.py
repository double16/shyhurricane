import queue
import time

import pytest

import shyhurricane.mcp_server.tools.port_scan as port_scan
from shyhurricane.utils import PortScanResults


async def noop(*args, **kwargs):
    return None


class LifespanContext:
    app_context_id = "ctx-1"


class RequestContext:
    lifespan_context = LifespanContext()


class Ctx:
    request_context = RequestContext()


class TaskQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class ResultQueue:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.requeued = []

    def get(self, timeout):
        if not self.items:
            raise queue.Empty
        return self.items.pop(0)

    def put(self, item, block=False):
        self.requeued.append(item)


class ServerContext:
    def __init__(self, results=None):
        self.open_world = True
        self.task_queue = TaskQueue()
        self.port_scan_result_queue = ResultQueue(results)
        self.stores = {"nmap": object(), "portscan": object()}


def scan_result(context_id="ctx-1", targets=None, has_more=False):
    return PortScanResults(
        context_id=context_id,
        results=[],
        targets=targets or ["example.com"],
        ports=["80"],
        runtime_ts=1.0,
        nmap_xml="<nmaprun/>",
        has_more=has_more,
        timestamp=time.time(),
    )


def patch_context(monkeypatch, server_context):
    async def get_fake_server_context():
        return server_context

    monkeypatch.setattr(port_scan, "get_server_context", get_fake_server_context)
    monkeypatch.setattr(port_scan, "log_tool_history", noop)
    monkeypatch.setattr(port_scan, "get_additional_hosts", lambda ctx, additional=None: additional or {})
    monkeypatch.setattr(port_scan, "get_stored_port_scan_results", lambda *args, **kwargs: None)


@pytest.mark.asyncio
async def test_port_scan_requires_target(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await port_scan.port_scan(Ctx(), hostnames="not a target", timeout_seconds=30)

    assert result.instructions.startswith("No targets")
    assert result.has_more is False
    assert ctx.task_queue.items == []


@pytest.mark.asyncio
async def test_port_scan_returns_stored_results(monkeypatch):
    stored = scan_result()
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)
    monkeypatch.setattr(port_scan, "get_stored_port_scan_results", lambda *args, **kwargs: stored)

    result = await port_scan.port_scan(Ctx(), hostnames="example.com", ports="80", retry=True)

    assert result.instructions == port_scan.port_scan_instructions
    assert result.nmap_xml == "<nmaprun/>"
    assert result.has_more is False
    assert ctx.task_queue.items == []


@pytest.mark.asyncio
async def test_port_scan_queues_work_and_returns_matching_result(monkeypatch):
    ctx = ServerContext([scan_result(context_id="other"), scan_result()])
    patch_context(monkeypatch, ctx)

    result = await port_scan.port_scan(
        Ctx(),
        hostnames="example.com",
        ports=[80],
        port_range_low=100,
        port_range_high=90,
        additional_hosts={"example.com": "127.0.0.1"},
        timeout_seconds=30,
    )

    queued = ctx.task_queue.items[0]
    assert queued.targets == ["example.com"]
    assert queued.ports == ["80", "90-100"]
    assert ctx.port_scan_result_queue.requeued[0].context_id == "other"
    assert result.instructions == port_scan.port_scan_instructions
    assert result.nmap_xml == "<nmaprun/>"


@pytest.mark.asyncio
async def test_port_scan_returns_pending_without_results(monkeypatch):
    ctx = ServerContext()
    patch_context(monkeypatch, ctx)

    result = await port_scan.port_scan(Ctx(), ip_addresses="127.0.0.1", timeout_seconds=30)

    assert result.instructions == port_scan.port_scan_instructions_no_results
    assert result.has_more is True
