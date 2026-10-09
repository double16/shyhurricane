"""Filesystem snapshot lifecycle, navigation, and failure behavior."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

from shyhurricane import result_pages
from shyhurricane.mcp_server.tools.get_result_page import get_result_page
from shyhurricane.result_pages import Pagination, ResultPageStore, SavedTextResult
from shyhurricane.result_pages import get_result_store as real_get_result_store


class Items(BaseModel):
    items: list[str]
    limit: int = 1
    pagination: Pagination | None = None


def snapshot(store, count=3):
    return store.save("test", [{"items": [str(i)]} for i in range(count)], 1, count)


def token_file(store, token):
    return store.tokens / f"{hashlib.sha256(token.encode()).hexdigest()}.json"


def test_navigation_restart_permissions_and_immutability(result_store):
    first, token = snapshot(result_store)
    assert first["pagination"]["previous_page_token"] is None
    assert len(token) == 43
    restarted = ResultPageStore(str(result_store.root.parent))
    middle = restarted.read(first["pagination"]["next_page_token"])["result"]
    last = restarted.read(middle["pagination"]["next_page_token"])["result"]
    assert middle["items"] == ["1"]
    assert last["items"] == ["2"]
    assert last["pagination"]["next_page_token"] is None
    assert restarted.read(middle["pagination"]["previous_page_token"])["result"] == first
    snapshot(result_store)
    assert restarted.read(token)["result"] == first
    for directory in (result_store.root, result_store.snapshots, result_store.tokens):
        assert directory.stat().st_mode & 0o777 == 0o700
    assert token_file(result_store, token).stat().st_mode & 0o777 == 0o600


def test_expiration_is_fixed_and_cleanup_is_idempotent(result_store, monkeypatch):
    now = 1000
    monkeypatch.setattr(result_pages.time, "time", lambda: now)
    first, token = snapshot(result_store)
    now += 86399
    assert result_store.read(token)["result"] == first
    result_store.cleanup()
    assert result_store.read(token)["result"] == first
    now += 1
    with pytest.raises(ToolError, match="expired"):
        result_store.read(token)
    result_store.cleanup()
    result_store.cleanup()
    assert not list(result_store.snapshots.iterdir())
    assert not list(result_store.tokens.iterdir())


@pytest.mark.parametrize("token", ["", "../manifest.json", "x" * 43, None, "a" * 100000])
def test_invalid_tokens_do_not_resolve_paths(result_store, token):
    with pytest.raises(ToolError, match="Repeat the original"):
        result_store.read(token)


@pytest.mark.parametrize(
    "change",
    [
        "missing_page",
        "bad_page",
        "missing_manifest",
        "bad_manifest",
        "old_version",
        "bad_count",
        "wrong_type",
        "bad_mapping",
        "bad_id",
        "bad_number",
        "out_of_range",
    ],
)
def test_corruption_is_rejected_and_cleaned(result_store, change):
    _, token = snapshot(result_store)
    directory = next(result_store.snapshots.iterdir())
    manifest_path = directory / "manifest.json"
    if change == "missing_page":
        (directory / "0.json").unlink()
    elif change == "bad_page":
        (directory / "0.json").write_text("{}")
    elif change == "missing_manifest":
        manifest_path.unlink()
    elif change == "bad_manifest":
        manifest_path.write_text("invalid")
    elif change in {"old_version", "bad_count", "wrong_type"}:
        manifest = json.loads(manifest_path.read_text())
        if change == "old_version":
            manifest["version"] = 99
        else:
            manifest["pages"] = 0 if change == "bad_count" else "two"
        manifest_path.write_text(json.dumps(manifest))
    else:
        mapping_path = token_file(result_store, token)
        mapping = json.loads(mapping_path.read_text())
        if change == "bad_mapping":
            mapping_path.write_text("[]")
        else:
            mapping.update(
                {"snapshot_id": "../outside"}
                if change == "bad_id"
                else {"page": "1" if change == "bad_number" else 999}
            )
            mapping_path.write_text(json.dumps(mapping))
    with pytest.raises(ToolError):
        result_store.read(token)
    result_store.cleanup()
    assert not token_file(result_store, token).exists()


def test_cleanup_orphans_and_temporary_files_preserves_valid_results(result_store):
    _, token = snapshot(result_store)
    directory = next(result_store.snapshots.iterdir())
    (directory / "abandoned.tmp").write_text("partial")
    (result_store.snapshots / "incomplete").mkdir()
    (result_store.snapshots / "unexpected.tmp").write_text("partial")
    (result_store.tokens / "orphan.tmp").write_text("partial")
    result_store.cleanup()
    assert len(list(result_store.snapshots.iterdir())) == 1
    assert not list(directory.glob("*.tmp"))
    assert result_store.read(token)
    assert len(list(result_store.tokens.iterdir())) == 3


def test_cleanup_continues_after_delete_errors(result_store, monkeypatch, caplog):
    (result_store.snapshots / "bad").mkdir()
    bad_token = result_store.tokens / "bad.tmp"
    bad_token.write_text("bad")
    original_unlink = Path.unlink

    def unlink(path, *args, **kwargs):
        if path == bad_token:
            raise PermissionError("denied")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(result_pages.shutil, "rmtree", lambda *args: (_ for _ in ()).throw(PermissionError()))
    monkeypatch.setattr(Path, "unlink", unlink)
    result_store.cleanup()
    assert "Failed to clean saved result" in caplog.text
    assert "Failed to clean page token" in caplog.text


def test_save_rolls_back_files_on_failure(result_store, monkeypatch):
    original_write = result_store._write
    calls = 0

    def fail(path, value):
        nonlocal calls
        calls += 1
        if calls == 6:
            raise OSError("disk full")
        original_write(path, value)

    monkeypatch.setattr(result_store, "_write", fail)
    with pytest.raises(OSError, match="disk full"):
        snapshot(result_store)
    assert not list(result_store.snapshots.iterdir())
    assert not list(result_store.tokens.iterdir())


def test_atomic_write_removes_failed_temporary_file(tmp_path, monkeypatch):
    target = tmp_path / "page.json"
    monkeypatch.setattr(result_pages.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        ResultPageStore._write(target, {})
    assert not target.exists()
    assert not target.with_suffix(".tmp").exists()


def test_invalid_ttl_and_empty_store(tmp_path):
    with pytest.raises(ValueError, match="positive integer"):
        ResultPageStore(str(tmp_path), 0)
    store = ResultPageStore(str(tmp_path), 1)
    assert store.save("test", [{"items": []}], 1, 0) == ({"items": []}, None)
    store.cleanup()


def test_concurrent_reads_saves_and_cleanup(result_store):
    _, token = snapshot(result_store)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for _ in range(10):
            futures.extend(
                [
                    executor.submit(snapshot, result_store),
                    executor.submit(result_store.read, token),
                    executor.submit(result_store.cleanup),
                ]
            )
        for future in futures:
            future.result()
    assert result_store.read(token)


@pytest.mark.asyncio
async def test_paginate_empty_single_multiple_and_write_errors(result_store, monkeypatch):
    empty = Items(items=[])
    assert await result_pages.paginate_result("test", empty, "items", 1) is empty
    single = await result_pages.paginate_result("test", Items(items=["a"]), "items", 1)
    assert single.pagination.total_pages == 1
    assert single.pagination.next_page_token is None
    multiple = await result_pages.paginate_result("test", Items(items=["a", "b", "c"]), "items", 2, True)
    assert multiple.items == ["a", "b"]
    assert multiple.limit == 2
    assert multiple.pagination.retrieval_truncated
    monkeypatch.setattr(result_store, "save", lambda *args: (_ for _ in ()).throw(OSError("full")))
    with pytest.raises(ToolError, match="Unable to save"):
        await result_pages.paginate_result("test", Items(items=["a"]), "items", 1)


@pytest.mark.asyncio
async def test_decorator_cleanup_validation_and_exactly_once(result_store, monkeypatch):
    calls = []
    cleanup = result_store.cleanup
    monkeypatch.setattr(result_store, "cleanup", lambda: (calls.append("clean"), cleanup()))

    @result_pages.paged_results("items")
    async def query(limit=2):
        calls.append("query")
        return Items(items=["a", "b", "c"])

    result = await query()
    assert calls == ["clean", "query"]
    assert result_store.read(result.pagination.next_page_token)["result"]["items"] == ["c"]
    assert calls == ["clean", "query"]
    for limit in (0, 1001, None, True):
        with pytest.raises(ToolError):
            await query(limit=limit)


@pytest.mark.asyncio
async def test_text_reconstructs_unicode_and_get_page_returns_discriminated_response(result_store):
    text = "π🙂\n世界" * 5
    result = await result_pages.paginate_result(
        "deobfuscate_javascript",
        SavedTextResult(text=text, mime_type="application/javascript", total_length=len(text)),
        "text",
        4,
    )
    chunks = [result.text]
    previous = result
    while previous.pagination.next_page_token:
        page = await get_result_page(None, previous.pagination.next_page_token)
        assert page.source_tool == "deobfuscate_javascript"
        assert page.result.offset == sum(map(len, chunks))
        assert page.result.total_length == len(text)
        chunks.append(page.result.text)
        previous = page.result
    assert "".join(chunks) == text
    assert not previous.has_more
    assert previous.pagination.expires_at == result.pagination.expires_at
    _, token = snapshot(result_store)
    with pytest.raises(ToolError, match="corrupt"):
        await get_result_page(None, token)


@pytest.mark.asyncio
async def test_saved_xml_empty_and_complete(result_store):
    empty, token = await result_pages.save_text("port_scan_xml", "", "application/xml")
    assert empty.text == "" and token is None
    first, token = await result_pages.save_text("port_scan_xml", "<nmap>hello</nmap>", "application/xml", 5)
    assert (await get_result_page(None, token)).result == first
    text = first.text
    while first.pagination.next_page_token:
        first = (await get_result_page(None, first.pagination.next_page_token)).result
        text += first.text
    assert text == "<nmap>hello</nmap>"


@pytest.mark.asyncio
async def test_content_decorator_validates_size_and_handles_none(result_store):
    @result_pages.paged_content("size", "text")
    async def text(size=2):
        return None

    assert await text() is None
    for size in (0, 4194305, True):
        with pytest.raises(ToolError):
            await text(size)


@pytest.mark.asyncio
async def test_real_store_getter(monkeypatch, result_store):
    import shyhurricane.mcp_server.server_context as server_context

    monkeypatch.setattr(
        server_context,
        "get_server_context",
        AsyncMock(
            return_value=type(
                "C",
                (),
                {
                    "result_store": result_store,
                },
            )()
        ),
    )
    assert await real_get_result_store() is result_store


def test_cleanup_does_not_follow_symbolic_links(result_store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    important = outside / "important.tmp"
    important.write_text("retain")
    (result_store.snapshots / ("a" * 32)).symlink_to(outside, target_is_directory=True)
    result_store.cleanup()
    assert important.read_text() == "retain"
    assert not list(result_store.snapshots.iterdir())
    _, token = snapshot(result_store)
    mapping = token_file(result_store, token)
    mapping.unlink()
    mapping.symlink_to(important)
    with pytest.raises(ToolError):
        result_store.read(token)
    result_store.cleanup()
    assert important.read_text() == "retain"


def test_cleanup_logs_enumeration_failure(result_store, monkeypatch, caplog):
    monkeypatch.setattr(Path, "iterdir", lambda *args: (_ for _ in ()).throw(PermissionError()))
    result_store.cleanup()
    assert "Failed to enumerate" in caplog.text


@pytest.mark.asyncio
async def test_xml_write_failure_is_tool_error(result_store, monkeypatch):
    monkeypatch.setattr(result_store, "save", lambda *args: (_ for _ in ()).throw(OSError("full")))
    with pytest.raises(ToolError, match="Unable to save"):
        await result_pages.save_text("port_scan_xml", "<xml/>", "application/xml")


@pytest.mark.asyncio
async def test_cancelled_snapshot_rolls_back_before_returning(result_store, monkeypatch):
    import asyncio
    from threading import Event

    entered = asyncio.Event()
    release = Event()
    loop = asyncio.get_running_loop()
    original_write = result_store._write
    calls = 0

    def write(path, value):
        nonlocal calls
        calls += 1
        if calls == 1:
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(5)
        original_write(path, value)

    monkeypatch.setattr(result_store, "_write", write)
    task = asyncio.create_task(result_pages.paginate_result("test", Items(items=["a", "b"]), "items", 1))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not list(result_store.snapshots.iterdir())
        assert not list(result_store.tokens.iterdir())
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
