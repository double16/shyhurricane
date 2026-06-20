import os
from types import SimpleNamespace

import pytest

import shyhurricane.mcp_server as mcp_server
import shyhurricane.mcp_server.server_context as server_context


class Proc:
    def __init__(self, return_code=0):
        self.return_code = return_code

    async def wait(self):
        return self.return_code


@pytest.mark.asyncio
async def test_app_lifespan_creates_context_and_cleans_work_path(monkeypatch, tmp_path):
    calls = []

    async def get_ctx():
        return SimpleNamespace(cache_path=str(tmp_path), mcp_session_volume="volume")

    async def create_subprocess_exec(*args, **kwargs):
        calls.append(args)
        return Proc(0)

    monkeypatch.setattr(mcp_server, "get_server_context", get_ctx)
    monkeypatch.setattr(mcp_server, "get_server_config", lambda: object())
    monkeypatch.setattr(mcp_server.asyncio, "create_subprocess_exec", create_subprocess_exec)
    monkeypatch.setattr(mcp_server, "unix_command_image", lambda: "image")

    async with mcp_server.app_lifespan(object()) as app_context:
        assert app_context.cache_path == str(tmp_path)
        assert app_context.work_path.startswith("/work/")

    assert calls[0][:3] == ("docker", "run", "--rm")
    assert "mkdir" in calls[0]
    assert "rm" in calls[1]


@pytest.mark.asyncio
async def test_app_lifespan_falls_back_when_workdir_creation_fails(monkeypatch, tmp_path):
    async def get_ctx():
        return SimpleNamespace(cache_path=str(tmp_path), mcp_session_volume="volume")

    async def create_subprocess_exec(*args, **kwargs):
        return Proc(1 if "mkdir" in args else 0)

    monkeypatch.setattr(mcp_server, "get_server_context", get_ctx)
    monkeypatch.setattr(mcp_server, "get_server_config", lambda: object())
    monkeypatch.setattr(mcp_server.asyncio, "create_subprocess_exec", create_subprocess_exec)
    monkeypatch.setattr(mcp_server, "unix_command_image", lambda: "image")

    async with mcp_server.app_lifespan(object()) as app_context:
        assert app_context.work_path == "/var/tmp"


@pytest.mark.asyncio
async def test_shyhurricane_fastmcp_filters_open_world_tools(monkeypatch):
    class Annotations:
        def __init__(self, open_world):
            self.openWorldHint = open_world

    tools = [
        SimpleNamespace(name="safe", annotations=Annotations(False)),
        SimpleNamespace(name="open", annotations=Annotations(True)),
        SimpleNamespace(name="plain", annotations=None),
    ]

    async def list_tools(self):
        return tools

    monkeypatch.setattr(mcp_server.FastMCP, "list_tools", list_tools)
    server = mcp_server.ShyHurricaneFastMCP("test")
    server.open_world = False

    assert [tool.name for tool in await server.list_tools()] == ["safe", "plain"]


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

    import shyhurricane.index.web_resources as web_resources
    import shyhurricane.task_queue as task_queue

    monkeypatch.setattr(server_context, "get_server_config", lambda: Config())
    monkeypatch.setattr(server_context, "create_qdrant_document_store", create_store)
    monkeypatch.setattr(server_context, "create_qdrant_client", create_client)
    monkeypatch.setattr(server_context, "build_stores", lambda db: stores)
    monkeypatch.setattr(server_context.subprocess, "check_call", lambda *args, **kwargs: None)
    monkeypatch.setattr(server_context.asyncio, "create_subprocess_exec", create_subprocess_exec)
    monkeypatch.setattr(web_resources, "start_ingest_worker", start_ingest_worker)
    monkeypatch.setattr(task_queue, "start_task_worker", start_task_worker)

    ctx = await server_context.get_server_context()

    assert ctx.db == "db"
    assert ctx.document_pipeline is None
    assert ctx.website_context_pipeline is None
    assert ctx.stores is stores
    assert ctx.qdrant_client == "client"
    assert ctx.open_world is False
    assert ctx.cache_path == os.path.join(str(tmp_path), "tool_cache")
    assert doc_stores and all(store.initialized for store in doc_stores)
