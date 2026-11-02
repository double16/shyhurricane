import asyncio
import os
import signal
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from mcp.types import CallToolResult

import shyhurricane.mcp_server as mcp_server
import shyhurricane.mcp_server.server_context as server_context
from shyhurricane.disk_space import DISK_DEFAULTS
from shyhurricane.task_queue.types import TaskPool, run_worker


class Proc:
    def __init__(self, return_code=0):
        self.return_code = return_code

    async def wait(self):
        return self.return_code


@pytest.mark.parametrize("value,disabled", [
    (None, False), ("", False), ("False", False), (" false ", False), ("0", False),
    ("no", False), ("off", False), ("True", True), ("1", True), ("yes", True),
])
def test_elicitation_environment_accepts_false_values(monkeypatch, value, disabled):
    if value is None:
        monkeypatch.delenv("DISABLE_ELICITATION", raising=False)
    else:
        monkeypatch.setenv("DISABLE_ELICITATION", value)
    assert server_context._elicitation_disabled() is disabled


def test_task_pool_terminates_monitor_worker_process_groups(monkeypatch):
    calls = []
    process = SimpleNamespace(pid=1234, _shyhurricane_monitor_process_group=True,
                              terminate=lambda: pytest.fail("terminate should not be called"),
                              join=lambda timeout=None: None, close=lambda: None, is_alive=lambda: False)
    monkeypatch.setenv("SHYHURRICANE_MONITOR", "1")
    def killpg(pid, sig):
        if sig == 0:
            raise ProcessLookupError
        calls.append((pid, sig))

    monkeypatch.setattr("shyhurricane.task_queue.types.os.killpg", killpg)

    TaskPool([process]).close()

    assert calls == [(1234, signal.SIGTERM)]


def test_run_worker_silences_output_in_monitor_mode(monkeypatch):
    calls = []
    monkeypatch.setenv("SHYHURRICANE_MONITOR", "1")
    monkeypatch.setattr("shyhurricane.task_queue.types.signal.signal", lambda sig, handler: calls.append((sig, handler)))
    monkeypatch.setattr("shyhurricane.task_queue.types.os.setsid", lambda: calls.append("setsid"))
    monkeypatch.setattr("shyhurricane.task_queue.types.os.dup2", lambda source, target: calls.append(target))

    run_worker(lambda: calls.append("worker"))

    assert calls == ["setsid", (signal.SIGINT, signal.SIG_IGN), 1, 2, "worker"]


@pytest.mark.asyncio
async def test_shyhurricane_fastmcp_filters_open_world_tools(monkeypatch):
    class Annotations:
        def __init__(self, open_world):
            self.open_world_hint = open_world

    tools = [
        SimpleNamespace(name="safe", annotations=Annotations(False)),
        SimpleNamespace(name="open", annotations=Annotations(True)),
        SimpleNamespace(name="plain", annotations=None),
    ]

    async def list_tools(self):
        return tools

    monkeypatch.setattr(mcp_server.MCPServer, "list_tools", list_tools)
    server = mcp_server.ShyHurricaneMCPServer("test")
    server.open_world = False

    assert [tool.name for tool in await server.list_tools()] == ["safe", "plain"]


@pytest.mark.asyncio
async def test_shyhurricane_fastmcp_tracks_running_tools_until_completion(monkeypatch):
    async def call_tool(self, name, arguments, context):
        assert server.running_tools == {"port_scan"}
        return {"result": "complete"}

    monkeypatch.setattr(mcp_server.MCPServer, "call_tool", call_tool)
    server = mcp_server.ShyHurricaneMCPServer("test")

    assert await server.call_tool("port_scan", {"target": "example.test"}) == {"result": "complete"}
    assert server.running_tools == set()


@pytest.mark.asyncio
async def test_shyhurricane_fastmcp_removes_failed_tools_from_monitor(monkeypatch):
    async def call_tool(self, name, arguments, context):
        assert server.running_tools == {"port_scan"}
        raise RuntimeError("failed")

    monkeypatch.setattr(mcp_server.MCPServer, "call_tool", call_tool)
    server = mcp_server.ShyHurricaneMCPServer("test")

    with pytest.raises(RuntimeError, match="failed"):
        await server.call_tool("port_scan", {"target": "example.test"})
    assert server.running_tools == set()


@pytest.mark.asyncio
async def test_same_tool_stays_visible_until_all_calls_finish_or_cancel(monkeypatch):
    server = mcp_server.ShyHurricaneMCPServer("test")
    first_started, second_started = asyncio.Event(), asyncio.Event()
    first_finish, second_finish = asyncio.Event(), asyncio.Event()
    contexts = []

    async def call_tool(self, name, arguments, context):
        contexts.append(context)
        started, finish = (first_started, first_finish) if arguments["first"] else (second_started, second_finish)
        started.set()
        await finish.wait()

    monkeypatch.setattr(mcp_server.MCPServer, "call_tool", call_tool)
    context = object()
    first = asyncio.create_task(server.call_tool("probe", {"first": True}, context))
    second = asyncio.create_task(server.call_tool("probe", {"first": False}, context))
    await first_started.wait()
    await second_started.wait()
    assert server.running_tools == {"probe"}
    first_finish.set()
    await first
    assert server.running_tools == {"probe"}
    second.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second
    assert server.running_tools == set()
    assert list(server.recent_tools) == [("probe", "failed"), ("probe", "complete")]
    assert server._running_tool_counts == {}
    assert contexts == [context, context]


@pytest.mark.asyncio
@pytest.mark.parametrize("pipeline_error", [None, RuntimeError, asyncio.CancelledError])
@pytest.mark.parametrize("compose", [False, True])
async def test_get_server_context_low_power_builds_context(monkeypatch, tmp_path, pipeline_error, compose):
    monkeypatch.setattr(server_context, "_server_context", None)
    monkeypatch.setattr(
        "shyhurricane.disk_space._disk_capacity",
        lambda path: (100 * 1024**3, 10 * 1024**3),
    )
    if compose:
        monkeypatch.setenv("TOOL_CACHE", str(tmp_path))
        monkeypatch.setenv("MCP_SESSION_VOLUME", "mcp_session")
    monkeypatch.setenv("DISABLE_ELICITATION", "")
    stores = {"content": object()}
    doc_stores = []
    qdrant_available = [False]
    monkeypatch.setattr(server_context, "qdrant_probe", lambda host, port: qdrant_available[0])
    monkeypatch.setattr(server_context.HealthMonitor, "start", lambda self: None)
    monkeypatch.setattr(server_context.HealthMonitor, "close", lambda self: None)
    pool_closes = []
    stop_events = []

    class Config:
        database = "db"
        data_dir = str(tmp_path)
        low_power = True
        ingest_pool_size = 2
        task_pool_size = 3
        open_world = False

    for name, default in DISK_DEFAULTS.items():
        setattr(Config, name, default)

    class Store:
        def __init__(self):
            self.initialized = False
            self.counted = False

        def _ensure_initialized(self):
            self.initialized = True

        def count_documents(self):
            self.counted = True

        def close(self):
            self.closed = True

    class Queue:
        path = "/queue"

    class Pool:
        def __init__(self):
            self.processes = []

        def close(self, deadline=None):
            pool_closes.append(deadline)

    class RuntimeEvent:
        def __init__(self):
            self.enabled = False

        def set(self):
            self.enabled = True

        def is_set(self):
            return self.enabled

        def clear(self):
            self.enabled = False

    class WorkerManager:
        def Event(self):
            return RuntimeEvent()

        def shutdown(self):
            pass

    async def create_client(db):
        return "client"

    async def create_subprocess_exec(*args, **kwargs):
        return Proc(0)

    def create_store(**kwargs):
        store = Store()
        doc_stores.append(store)
        return store

    log_timestamps = []
    startup_events = []
    page_cleanups = []
    cleanup_pages = server_context.ResultPageStore.cleanup

    def record_page_cleanup(store):
        page_cleanups.append(store)
        cleanup_pages(store)

    monkeypatch.setattr(server_context.ResultPageStore, "cleanup", record_page_cleanup)

    def start_ingest_worker(**kwargs):
        assert startup_events == [("cleanup", "db")]
        startup_events.append(("ingest", "db"))
        log_timestamps.append(kwargs["log_timestamp"])
        stop_events.append(kwargs["stop_event"])
        assert kwargs["health_state"] is not None
        return Queue(), Pool()

    def start_task_worker(*args, stop_event=None):
        assert stop_event is not None
        assert startup_events == [("cleanup", "db"), ("ingest", "db")]
        assert args[3] == log_timestamps[0]
        return SimpleNamespace(
            task_queue="task",
            task_pool=Pool(),
            spider_result_queue="spider",
            port_scan_result_queue="ports",
            dir_busting_result_queue="dirs",
        )

    async def build_document_pipeline(db, generator_config):
        if pipeline_error is not None:
            raise pipeline_error("pipeline interrupted")
        return object(), None, stores

    import shyhurricane.index.web_resources as web_resources
    import shyhurricane.task_queue as task_queue

    monkeypatch.setattr(server_context, "get_server_config", lambda: Config())
    monkeypatch.setattr(server_context, "cleanup_persistent_queues_on_startup",
                        lambda db: startup_events.append(("cleanup", db)))
    monkeypatch.setattr(server_context.multiprocessing, "Manager", WorkerManager)
    monkeypatch.setattr(server_context, "create_qdrant_document_store", create_store)
    monkeypatch.setattr(server_context, "create_qdrant_client", create_client)
    monkeypatch.setattr(server_context, "qdrant_host_port", lambda db: ("127.0.0.1", 49201))
    monkeypatch.setattr(server_context, "build_document_pipeline", build_document_pipeline)
    monkeypatch.setattr(server_context, "build_website_context_pipeline", lambda generator_config: object())
    monkeypatch.setattr(server_context.subprocess, "check_call", lambda *args, **kwargs: None)
    monkeypatch.setattr(server_context.asyncio, "create_subprocess_exec", create_subprocess_exec)
    monkeypatch.setattr(web_resources, "start_ingest_worker", start_ingest_worker)
    monkeypatch.setattr(task_queue, "start_task_worker", start_task_worker)
    monkeypatch.setattr("shyhurricane.graph.worker.start_graph_worker", lambda *args: object())
    monkeypatch.setattr("shyhurricane.investigation.worker.start_investigation_worker", lambda *args: object())
    monkeypatch.setattr(server_context, "GraphStore", lambda location: SimpleNamespace(
        location=location, ready=lambda: True, close=lambda: None, schema_ready=True))
    monkeypatch.setattr(server_context, "GraphMaintenance", MagicMock())

    if pipeline_error is not None:
        with pytest.raises(pipeline_error, match="pipeline interrupted"):
            await server_context.get_server_context()
        assert server_context._server_context is None
        assert stop_events[0].is_set()
        assert len(pool_closes) == 2
        assert pool_closes[0] == pool_closes[1]
        return

    ctx = await server_context.get_server_context()

    assert ctx.health_monitor.disk_guard.snapshot()["path"] == str(tmp_path)
    assert ctx.db == "db"
    assert ctx.document_pipeline is not None
    assert ctx.website_context_pipeline is not None
    assert ctx.stores is stores
    assert not ctx.indexing_enabled.is_set()
    assert ctx.qdrant_client == "client"
    assert (ctx.qdrant_host, ctx.qdrant_port) == ("127.0.0.1", 49201)
    assert ctx.open_world is False
    assert ctx.disable_elicitation is False
    assert ctx.cache_path == os.path.join(str(tmp_path), "tool_cache")
    assert ctx.mcp_session_volume == ("mcp_session" if compose else str(tmp_path / "sessions"))
    assert page_cleanups == [ctx.result_store]
    assert not doc_stores
    assert not ctx.health_monitor.check()
    assert not ctx.health_monitor.ready.is_set()
    qdrant_available[0] = True
    assert ctx.health_monitor.check()
    assert ctx.health_monitor.ready.is_set()
    assert ctx.health_monitor.disk_guard.snapshot()["state"] == "healthy"
    assert doc_stores and all(store.initialized and store.closed for store in doc_stores)
    ctx.graph_maintenance.start.assert_called_once()
    ctx.close()
    assert page_cleanups == [ctx.result_store, ctx.result_store]


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", ["0", "-1", "invalid"])
async def test_invalid_result_ttl_fails_before_services_start(monkeypatch, tmp_path, ttl):
    monkeypatch.setattr(server_context, "_server_context", None)
    monkeypatch.setenv("TOOL_CACHE", str(tmp_path))
    monkeypatch.setenv("TOOL_RESULT_TTL_SECONDS", ttl)
    monkeypatch.setattr(server_context, "doc_type_to_model", lambda: pytest.fail("Services must not initialize"))
    with pytest.raises(ValueError):
        await server_context.get_server_context()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["complete", "error_result", "exception"])
async def test_tool_history_records_outcomes_and_evicts_oldest(monkeypatch, outcome):
    result = CallToolResult(content=[], is_error=outcome == "error_result")

    async def call_tool(self, name, arguments, context):
        if outcome == "exception":
            raise RuntimeError("failure")
        return result

    monkeypatch.setattr(mcp_server.MCPServer, "call_tool", call_tool)
    server = mcp_server.ShyHurricaneMCPServer("test")
    assert list(server.recent_tools) == []
    for index in range(7):
        if outcome == "exception":
            with pytest.raises(RuntimeError, match="failure"):
                await server.call_tool(f"tool_{index}", {})
        else:
            assert await server.call_tool(f"tool_{index}", {}) is result
    status = "complete" if outcome == "complete" else "failed"
    assert list(server.recent_tools) == [(f"tool_{index}", status) for index in range(6, 1, -1)]
    assert server.running_tools == set()


@pytest.mark.parametrize("ensure_initialized", [False, True])
def test_qdrant_readiness_retries_partial_initialization_and_recovers(monkeypatch, ensure_initialized):
    models = {"test": SimpleNamespace(get_qdrant_collections=lambda: ["first", "second"])}
    monkeypatch.setattr(server_context, "doc_type_to_model", lambda: models)
    probes = iter([ConnectionError("starting"), False, True, True, True, ConnectionError("down"), True])
    stores = []

    def probe(host, port):
        assert (host, port) == ("host", 6333)
        result = next(probes)
        if isinstance(result, Exception):
            raise result
        return result

    def create_store(db, index):
        assert db == "remote:6333"
        store = SimpleNamespace(index=index, closed=False)

        def initialize():
            if len(stores) == 2:
                raise ConnectionError("collection setup failed")

        def close():
            store.closed = True

        store.close = close
        if ensure_initialized:
            store._ensure_initialized = initialize
        else:
            store.count_documents = initialize
        stores.append(store)
        return store

    monkeypatch.setattr(server_context, "qdrant_probe", probe)
    monkeypatch.setattr(server_context, "create_qdrant_document_store", create_store)
    monitor = server_context.HealthMonitor(
        server_context._qdrant_readiness_probe("remote:6333", "host", 6333), lambda: True,
    )
    for _ in range(3):
        assert not monitor.check()
        assert not monitor.ready.is_set()
    assert [store.index for store in stores] == ["first", "second"]
    assert all(store.closed for store in stores)
    assert monitor.check()
    assert monitor.ready.is_set()
    assert [store.index for store in stores] == ["first", "second", "first", "second"]
    assert all(store.closed for store in stores)
    assert monitor.check()
    assert not monitor.check()
    assert not monitor.ready.is_set()
    assert monitor.check()
    assert monitor.ready.is_set()
    assert len(stores) == 4
