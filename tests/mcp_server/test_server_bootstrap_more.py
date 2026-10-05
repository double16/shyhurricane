import asyncio
import os
import signal
from types import SimpleNamespace

import pytest

import shyhurricane.mcp_server as mcp_server
import shyhurricane.mcp_server.server_context as server_context
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
                              join=lambda: None, close=lambda: None)
    monkeypatch.setenv("SHYHURRICANE_MONITOR", "1")
    monkeypatch.setattr("shyhurricane.task_queue.types.os.killpg", lambda pid, sig: calls.append((pid, sig)))

    TaskPool([process]).close()

    assert calls == [(1234, signal.SIGTERM)]


def test_run_worker_silences_output_in_monitor_mode(monkeypatch):
    calls = []
    monkeypatch.setenv("SHYHURRICANE_MONITOR", "1")
    monkeypatch.setattr("shyhurricane.task_queue.types.signal.signal", lambda sig, handler: calls.append((sig, handler)))
    monkeypatch.setattr("shyhurricane.task_queue.types.os.setsid", lambda: calls.append("setsid"))
    monkeypatch.setattr("shyhurricane.task_queue.types.os.dup2", lambda source, target: calls.append(target))

    run_worker(lambda: calls.append("worker"))

    assert calls == [(signal.SIGINT, signal.SIG_IGN), "setsid", 1, 2, "worker"]


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
    assert server._running_tool_counts == {}
    assert contexts == [context, context]


@pytest.mark.asyncio
async def test_get_server_context_low_power_builds_context(monkeypatch, tmp_path):
    monkeypatch.setattr(server_context, "_server_context", None)
    monkeypatch.setenv("TOOL_CACHE", str(tmp_path))
    monkeypatch.setenv("DISABLE_ELICITATION", "")
    stores = {"content": object()}
    doc_stores = []

    class Config:
        database = "db"
        low_power = True
        ingest_pool_size = 2
        task_pool_size = 3
        open_world = False

    class Store:
        def __init__(self):
            self.initialized = False
            self.counted = False

        def _ensure_initialized(self):
            self.initialized = True

        def count_documents(self):
            self.counted = True

    class Queue:
        path = "/queue"

    class Pool:
        def close(self):
            pass

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

    def start_ingest_worker(**kwargs):
        return Queue(), Pool()

    def start_task_worker(*args):
        return SimpleNamespace(
            task_queue="task",
            task_pool=Pool(),
            spider_result_queue="spider",
            port_scan_result_queue="ports",
            dir_busting_result_queue="dirs",
        )

    async def build_document_pipeline(db, generator_config):
        return object(), None, stores

    import shyhurricane.index.web_resources as web_resources
    import shyhurricane.task_queue as task_queue

    monkeypatch.setattr(server_context, "get_server_config", lambda: Config())
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

    ctx = await server_context.get_server_context()

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
    assert doc_stores and all(store.initialized for store in doc_stores)
    ctx.close()
