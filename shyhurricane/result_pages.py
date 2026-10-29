"""Immutable filesystem snapshots and bearer-token page navigation."""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from inspect import signature
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

from shyhurricane.graph.budget import page_budget, paging

logger = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"[0-9a-f]{32}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class Pagination(BaseModel):
    page_number: int
    page_size: int
    total_items: int
    total_pages: int
    expires_at: str
    next_page_token: str | None = Field(
        None, description="Pass to get_result_page for the next saved page; null means no additional saved page"
    )
    previous_page_token: str | None = None
    retrieval_truncated: bool = False


class SavedTextResult(BaseModel):
    text: str
    mime_type: str
    offset: int = 0
    total_length: int
    pagination: Pagination | None = None


class ResultPageStore:
    def __init__(self, cache_path: str, ttl_seconds: int = 86400):
        if ttl_seconds <= 0:
            raise ValueError("TOOL_RESULT_TTL_SECONDS must be a positive integer")
        self.root = Path(cache_path) / "result_pages"
        self.snapshots = self.root / "snapshots"
        self.tokens = self.root / "tokens"
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._maintenance = None
        self._maintenance_stop = threading.Event()
        self._cleanup_entries = None
        for path in (self.root, self.snapshots, self.tokens):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)

    def start_maintenance(self):
        if self._maintenance is None:
            def maintain():
                while not self._maintenance_stop.wait(60):
                    self.cleanup_batch()
            self._maintenance = threading.Thread(target=maintain, name="saved-page-cleanup", daemon=True)
            self._maintenance.start()

    def close(self):
        self._maintenance_stop.set()
        if self._maintenance is not None:
            self._maintenance.join(timeout=2)

    def cleanup_batch(self):
        """Inspect at most 100 entries or one second; reads verify page integrity."""
        started = time.monotonic()
        if self._cleanup_entries is None:
            from itertools import chain
            self._cleanup_entries = chain(self.snapshots.iterdir(), self.tokens.iterdir())
        for _ in range(100):
            if time.monotonic() - started >= 1:
                break
            if not self._lock.acquire(blocking=False):
                break
            try:
                path = next(self._cleanup_entries, None)
                if path is None:
                    self._cleanup_entries = None
                    break
                try:
                    if path.parent == self.snapshots:
                        self._manifest(path.name)
                    else:
                        mapping = self._read(path)
                        manifest = self._manifest(mapping["snapshot_id"])
                        if type(mapping["page"]) is not int or not 0 <= mapping["page"] < manifest["pages"]:
                            raise ValueError("Invalid token page")
                except (OSError, ValueError, KeyError, TypeError):
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Failed saved-page maintenance pass")
                self._cleanup_entries = None
                break
            finally:
                self._lock.release()

    @contextmanager
    def saving(self, cancelled, budget):
        while not self._lock.acquire(timeout=0.05):
            self._check_save(cancelled, budget)
        try:
            self._check_save(cancelled, budget)
            yield
        finally:
            self._lock.release()

    @staticmethod
    def _check_save(cancelled, budget):
        if cancelled is not None and cancelled.is_set():
            raise OSError("Snapshot creation cancelled")
        if budget is not None:
            budget.check()

    @staticmethod
    def _write(path: Path, value: dict, cancelled=None, budget=None) -> None:
        temporary = path.with_suffix(".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                for chunk in json.JSONEncoder(ensure_ascii=False).iterencode(value):
                    ResultPageStore._check_save(cancelled, budget)
                    stream.write(chunk)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _read(path: Path, digest: str | None = None) -> dict:
        if path.is_symlink():
            raise ValueError("Snapshot files must not be symbolic links")
        data = path.read_bytes()
        if digest is not None and hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Snapshot page failed integrity check")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("Invalid snapshot object")
        return value

    def save(
        self,
        source_tool: str,
        pages: list[dict],
        page_size: int,
        total_items: int,
        retrieval_truncated: bool = False,
        cancelled: threading.Event | None = None,
        budget=None,
    ) -> tuple[dict, str | None]:
        if not total_items:
            return pages[0], None
        with self.saving(cancelled, budget):
            snapshot_id = uuid.uuid4().hex
            directory = self.snapshots / snapshot_id
            directory.mkdir(mode=0o700)
            tokens = [secrets.token_urlsafe(32) for _ in pages]
            expires = time.time() + self.ttl_seconds
            expires_at = datetime.fromtimestamp(expires, timezone.utc).isoformat()
            mappings = []
            digests = []
            try:
                for number, page in enumerate(pages):
                    if cancelled is not None and cancelled.is_set():
                        raise OSError("Snapshot creation cancelled")
                    page["pagination"] = Pagination(
                        page_number=number + 1,
                        page_size=page_size,
                        total_items=total_items,
                        total_pages=len(pages),
                        expires_at=expires_at,
                        previous_page_token=tokens[number - 1] if number else None,
                        next_page_token=tokens[number + 1] if number + 1 < len(pages) else None,
                        retrieval_truncated=retrieval_truncated,
                    ).model_dump()
                    path = directory / f"{number}.json"
                    self._write(path, {"source_tool": source_tool, "result": page}, cancelled, budget)
                    digests.append(hashlib.sha256(path.read_bytes()).hexdigest())
                self._write(
                    directory / "manifest.json",
                    {
                        "version": 1,
                        "expires": expires,
                        "pages": len(pages),
                        "digests": digests,
                    },
                )
                for number, token in enumerate(tokens):
                    path = self.tokens / f"{hashlib.sha256(token.encode()).hexdigest()}.json"
                    mappings.append(path)
                    self._write(path, {"snapshot_id": snapshot_id, "page": number})
                if cancelled is not None and cancelled.is_set():
                    raise OSError("Snapshot creation cancelled")
            except BaseException:
                for path in mappings:
                    path.unlink(missing_ok=True)
                shutil.rmtree(directory)
                raise
            return pages[0], tokens[0]

    def _manifest(self, snapshot_id: str) -> dict:
        if not isinstance(snapshot_id, str) or not _IDENTIFIER.fullmatch(snapshot_id):
            raise ValueError("Invalid snapshot identifier")
        directory = self.snapshots / snapshot_id
        if directory.is_symlink():
            raise ValueError("Snapshot directories must not be symbolic links")
        manifest = self._read(directory / "manifest.json")
        if manifest["version"] != 1 or manifest["expires"] <= time.time():
            raise ValueError("Snapshot expired or unsupported")
        if type(manifest["pages"]) is not int or manifest["pages"] < 1:
            raise ValueError("Invalid page count")
        if not isinstance(manifest["digests"], list) or len(manifest["digests"]) != manifest["pages"]:
            raise ValueError("Invalid page integrity metadata")
        return manifest

    def read(self, token: str) -> dict:
        try:
            if not isinstance(token, str) or not _TOKEN.fullmatch(token):
                raise ValueError("Invalid token")
            with self._lock:
                mapping = self._read(self.tokens / f"{hashlib.sha256(token.encode()).hexdigest()}.json")
                manifest = self._manifest(mapping["snapshot_id"])
                number = mapping["page"]
                if type(number) is not int or not 0 <= number < manifest["pages"]:
                    raise ValueError("Invalid page")
                page = self._read(
                    self.snapshots / mapping["snapshot_id"] / f"{number}.json", manifest["digests"][number]
                )
                if "source_tool" not in page or "result" not in page:
                    raise ValueError("Invalid saved page")
                return page
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ToolError("Saved result is unavailable or expired. Repeat the original operation.") from error

    def cleanup(self) -> None:
        """Remove expired/corrupt snapshots and orphan tokens; retain valid results."""
        try:
            self._cleanup()
        except OSError:
            logger.exception("Failed to enumerate saved results for cleanup")

    def _cleanup(self) -> None:
        with self._lock:
            for directory in self.snapshots.iterdir():
                try:
                    manifest = self._manifest(directory.name)
                    for number in range(manifest["pages"]):
                        page = self._read(directory / f"{number}.json", manifest["digests"][number])
                        if "result" not in page or "source_tool" not in page:
                            raise ValueError("Invalid saved page")
                    for temporary in directory.glob("*.tmp"):
                        temporary.unlink(missing_ok=True)
                    continue
                except (OSError, ValueError, KeyError, TypeError):
                    pass
                try:
                    if directory.is_dir() and not directory.is_symlink():
                        shutil.rmtree(directory)
                    else:
                        directory.unlink(missing_ok=True)
                except OSError:
                    logger.exception("Failed to clean saved result %s", directory.name)
            for path in self.tokens.iterdir():
                try:
                    mapping = self._read(path)
                    manifest = self._manifest(mapping["snapshot_id"])
                    if path.suffix != ".json" or type(mapping["page"]) is not int:
                        raise ValueError("Invalid token mapping")
                    if not 0 <= mapping["page"] < manifest["pages"]:
                        raise ValueError("Invalid token page")
                    continue
                except (OSError, ValueError, KeyError, TypeError):
                    pass
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    logger.exception("Failed to clean page token %s", path.name)


async def get_result_store() -> ResultPageStore:
    from shyhurricane.mcp_server.server_context import get_server_context

    return (await get_server_context()).result_store


async def start_query() -> ResultPageStore:
    store = await get_result_store()
    store.start_maintenance()
    return store


async def _save_pages(
    store: ResultPageStore,
    source_tool: str,
    pages: list[dict],
    page_size: int,
    total_items: int,
    retrieval_truncated: bool = False,
    save_failure_message: str | None = None,
):
    cancelled = threading.Event()
    budget = page_budget.get()
    task = asyncio.create_task(
        asyncio.to_thread(
            store.save,
            source_tool,
            pages,
            page_size,
            total_items,
            retrieval_truncated,
            cancelled,
            budget,
        )
    )
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancelled.set()
        try:
            await asyncio.shield(task)
        except OSError:
            pass
        raise
    except OSError as error:
        raise ToolError(
            save_failure_message or "Unable to save result pages. Repeat the original operation."
        ) from error


async def paginate_result(
    source_tool: str, result: BaseModel, field: str, page_size: int, retrieval_truncated: bool = False,
    save_failure_message: str | None = None,
) -> BaseModel:
    budget = page_budget.get()
    started = time.monotonic()
    if budget is not None:
        budget.checkpointing += 1
    try:
        return await _paginate_result(source_tool, result, field, page_size, retrieval_truncated, save_failure_message)
    except (TimeoutError, ToolError):
        if budget is None or not hasattr(result, "analysis_gaps"):
            raise
        return result.model_copy(update={
            "pagination": None, "retrieval_truncated": True,
            "analysis_gaps": [*result.analysis_gaps, "Result page saving exceeded its budget; restart required"],
            "truncation_reasons": sorted(set(result.truncation_reasons) | {"time_limit"}),
        })
    finally:
        if budget is not None:
            budget.checkpointing -= 1
            logger.debug("Graph request=%s stage=pagination seconds=%.3f",
                         budget.request_id, time.monotonic() - started)


async def _paginate_result(source_tool, result, field, page_size, retrieval_truncated, save_failure_message):
    store = await get_result_store()
    value = result.model_dump(mode="json")
    nested = field == "contents.text"
    items = value["contents"]["text"] if nested else value[field]
    pages = []
    for offset in range(0, len(items), page_size):
        if page_budget.get() is not None:
            page_budget.get().check()
        chunk = items[offset : offset + page_size]
        if nested:
            page = {
                **value,
                "contents": {
                    **value["contents"],
                    "text": chunk,
                    "offset": offset,
                    "total_length": len(items),
                },
            }
        else:
            page = {**value, field: chunk}
        if source_tool == "find_investigation_targets":
            contributors = {key for item in chunk for key in item["finding_ids"]}
            page["findings"] = {
                key: context for key, context in value.get("findings", {}).items() if key in contributors
            }
        if "limit" in page:
            page["limit"] = page_size
        if isinstance(result, SavedTextResult):
            page.update(offset=offset)
        pages.append(page)
    if not pages:
        return result
    first, _ = await _save_pages(
        store, source_tool, pages, page_size, len(items), retrieval_truncated, save_failure_message
    )
    return type(result).model_validate(first)


def paged_results(field: str):
    """Paginate the complete result after execution."""

    def decorate(function):
        function_signature = signature(function)

        @wraps(function)
        async def wrapped(*args, **kwargs):
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            page_size = bound.arguments["limit"]
            if type(page_size) is not int or not 1 <= page_size <= 1000:
                raise ToolError("limit must be between 1 and 1000")
            await start_query()
            token = page_budget.set(None)
            paging_token = paging.set(True)
            try:
                result = await function(*bound.args, **bound.kwargs)
                return await paginate_result(
                    function.__name__, result, field, page_size,
                    bool(result.model_dump().get("retrieval_truncated", False)),
                )
            finally:
                page_budget.reset(token)
                paging.reset(paging_token)

        return wrapped

    return decorate


async def save_text(source_tool: str, text: str, mime_type: str, page_size: int = 8192):
    result = SavedTextResult(text=text, mime_type=mime_type, total_length=len(text))
    if not text:
        return result, None
    store = await get_result_store()
    pages = []
    for offset in range(0, len(text), page_size):
        pages.append(
            result.model_copy(
                update={
                    "text": text[offset : offset + page_size],
                    "offset": offset,
                }
            ).model_dump(mode="json")
        )
    first, token = await _save_pages(store, source_tool, pages, page_size, len(text))
    return SavedTextResult.model_validate(first), token


def paged_content(size_argument: str, field: str, save_failure_message: str | None = None):
    def decorate(function):
        function_signature = signature(function)

        @wraps(function)
        async def wrapped(*args, **kwargs):
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            size = bound.arguments[size_argument]
            if type(size) is not int or not 1 <= size <= 4 * 1024 * 1024:
                raise ToolError("Content page size must be between 1 and 4194304 characters")
            await start_query()
            result = await function(*bound.args, **bound.kwargs)
            if result is None or (field == "contents.text" and result.contents is None):
                return result
            return await paginate_result(
                function.__name__, result, field, size, save_failure_message=save_failure_message
            )

        return wrapped

    return decorate
