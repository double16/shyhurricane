import io
import importlib
import time
from xml.etree import ElementTree as ET

from haystack import Document

worker = importlib.import_module("shyhurricane.task_queue.port_scan_worker")
from shyhurricane.task_queue.port_scan_worker import (
    NMAP_DOCUMENT_VERSION,
    PortScanContext,
    _do_port_scan,
    get_stored_port_scan_results,
    port_scan_worker,
)
from shyhurricane.task_queue.types import PortScanQueueItem


class Embedder:
    def __init__(self):
        self.warmed = False

    def warm_up(self):
        self.warmed = True

    def run(self, documents):
        return {"documents": documents}


class Store:
    def __init__(self, docs=None):
        self.docs = docs or []
        self.filters = []
        self.written = []

    def filter_documents(self, filters):
        self.filters.append(filters)
        return self.docs

    def write_documents(self, documents, policy):
        self.written.append((documents, policy))


class ResultQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)

    def put_nowait(self, item):
        self.items.append(item)


def test_port_scan_context_initializes_stores_and_warms_embedders(monkeypatch):
    stores = []

    def create_store(db, index):
        store = Store()
        stores.append((index, store))
        return store

    class Cache:
        def get(self, config):
            return Embedder()

    monkeypatch.setattr(worker, "create_qdrant_document_store", create_store)

    ctx = PortScanContext("db", Cache())
    ctx.warm_up()

    assert [name for name, store in stores] == ["nmap", "portscan"]
    assert ctx.nmap_embedder.warmed is True
    assert ctx.portscan_embedder.warmed is True


def test_get_stored_port_scan_results_returns_newest_matching_result():
    runtime_old = time.time() - 100
    runtime_new = time.time() - 10
    nmap_docs = [
        Document(content="<old/>", meta={"runtime_ts": runtime_old, "ports": "80", "version": NMAP_DOCUMENT_VERSION}),
        Document(content="<new/>",
                 meta={"runtime_ts": runtime_new, "ports": "80,443", "version": NMAP_DOCUMENT_VERSION}),
        Document(content="ERROR: Script execution failed", meta={"runtime_ts": time.time(), "ports": "80"}),
    ]
    portscan_doc = Document(
        content='{"hostname":"","ip_address":"127.0.0.1","port":80,"state":"open","service_name":"http","service_notes":""}',
        meta={"runtime_ts": runtime_new},
    )
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=False)

    result = get_stored_port_scan_results(item, Store(nmap_docs), Store([portscan_doc]))

    assert result.nmap_xml == "<new/>"
    assert result.runtime_ts == runtime_new
    assert result.results[0].port == 80


def test_get_stored_port_scan_results_ignores_expired_or_uncovered_results():
    expired = Document(content="<expired/>", meta={"runtime_ts": time.time() - 8 * 24 * 3600, "ports": "80"})
    uncovered = Document(content="<uncovered/>", meta={"runtime_ts": time.time(), "ports": "443"})
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=False)

    assert get_stored_port_scan_results(item, Store([expired, uncovered]), Store([])) is None


class FakeProc:
    def __init__(self, return_code):
        self.return_code = return_code

    def wait(self):
        return self.return_code


class FileWithFileno(io.StringIO):
    def fileno(self):
        return 1


class TemporaryFile:
    def __init__(self, content):
        self.file = FileWithFileno(content)

    def __enter__(self):
        return self.file

    def __exit__(self, exc_type, exc, tb):
        return None


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="x" output="note"/>
        <extrareasons reason="syn-ack"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_do_port_scan_runs_nmap_parses_xml_writes_documents_and_queues_result(monkeypatch):
    nmap_store = Store()
    portscan_store = Store()
    result_queue = ResultQueue()
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=True)

    monkeypatch.setattr(worker.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(worker.tempfile, "TemporaryFile", lambda mode: TemporaryFile(NMAP_XML))
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: FakeProc(0))
    monkeypatch.setattr(worker, "safe_embedder", lambda embedder, docs: docs)

    _do_port_scan(result_queue, item, nmap_store, Embedder(), portscan_store, Embedder())

    result = result_queue.items[0]
    assert result.context_id == "ctx"
    assert result.results[0].ip_address == "127.0.0.1"
    assert result.results[0].service_name == "http"
    assert "extrareasons" not in result.nmap_xml
    assert len(nmap_store.written) == 1
    assert len(portscan_store.written) == 1


def test_do_port_scan_returns_stored_result_without_running(monkeypatch):
    stored = get_stored_port_scan_results(
        PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=False),
        Store([Document(content="<stored/>", meta={"runtime_ts": time.time(), "ports": "80"})]),
        Store([]),
    )
    result_queue = ResultQueue()
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=False)
    monkeypatch.setattr(worker, "get_stored_port_scan_results", lambda *args, **kwargs: stored)

    _do_port_scan(result_queue, item, Store(), Embedder(), Store(), Embedder())

    assert result_queue.items[0].nmap_xml == "<stored/>"


def test_do_port_scan_handles_failed_or_invalid_nmap(monkeypatch):
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["80"], {}, retry=True)
    result_queue = ResultQueue()

    monkeypatch.setattr(worker.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(worker.tempfile, "TemporaryFile", lambda mode: TemporaryFile("<not-xml"))
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: FakeProc(1))
    _do_port_scan(result_queue, item, Store(), Embedder(), Store(), Embedder())
    assert result_queue.items == []

    monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: FakeProc(0))
    _do_port_scan(result_queue, item, Store(), Embedder(), Store(), Embedder())
    assert result_queue.items == []


def test_port_scan_worker_runs_top_ports_first_when_many_ports(monkeypatch):
    calls = []

    class Ctx:
        nmap_store = Store()
        nmap_embedder = Embedder()
        portscan_store = Store()
        portscan_embedder = Embedder()

    monkeypatch.setattr(worker, "_do_port_scan", lambda *args: calls.append(args[1].ports.copy()))
    item = PortScanQueueItem("ctx", ["127.0.0.1"], ["1-65535"], {}, retry=False)

    port_scan_worker(Ctx(), item, ResultQueue())

    assert len(calls) == 2
    assert calls[-1] == ["1-65535"]
