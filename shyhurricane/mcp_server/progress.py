"""Report client progress with counters scoped to an inbound tool request."""

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from typing import ParamSpec, TypeVar

from mcp.server.mcpserver import Context
from mcp.server.session import ServerSession

_P = ParamSpec("_P")
_R = TypeVar("_R")
logger = logging.getLogger(__name__)
PROGRESS_INTERVAL_SECONDS = 20.0
LONG_RUNNING_TOOLS = frozenset({
    "spider_website",
    "directory_buster",
    "port_scan",
    "find_web_resources",
    "deobfuscate_javascript",
    "index_http_url",
})


class ProgressReporter:
    def __init__(self) -> None:
        self.count = 0
        self.lock = asyncio.Lock()
        self.last_progress = time.monotonic()

    async def report(self, ctx: Context | ServerSession, message: str) -> None:
        async with self.lock:
            self.count += 1
            await ctx.report_progress(self.count, message=message)
            self.last_progress = time.monotonic()

    async def heartbeat(self, ctx: Context | ServerSession, message: str) -> None:
        while True:
            await asyncio.sleep(max(0, self.last_progress + PROGRESS_INTERVAL_SECONDS - time.monotonic()))
            failed = False
            async with self.lock:
                if time.monotonic() - self.last_progress < PROGRESS_INTERVAL_SECONDS:
                    continue
                self.count += 1
                try:
                    await ctx.report_progress(self.count, message=message)
                except Exception:
                    logger.warning("Failed to send idle progress", exc_info=True)
                    failed = True
                else:
                    self.last_progress = time.monotonic()
            if failed:
                # Back off without holding the notification lock or recording delivery.
                await asyncio.sleep(PROGRESS_INTERVAL_SECONDS)


_reporter: ContextVar[ProgressReporter | None] = ContextVar("shyhurricane_progress", default=None)


@asynccontextmanager
async def idle_progress(ctx: Context | ServerSession, tool_name: str) -> AsyncIterator[None]:
    """Own one idle timer for an eligible inbound call, including argument resolution."""
    reporter = _reporter.get()
    if tool_name not in LONG_RUNNING_TOOLS or reporter is None:
        yield
        return
    task = asyncio.create_task(reporter.heartbeat(ctx, f"{tool_name} is still running"))
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def progress_scope(
    *, fresh: bool = False,
) -> Callable[[Callable[_P, Awaitable[_R]]], Callable[_P, Awaitable[_R]]]:
    """Share nested operations' counters and discard them on return or cancellation."""
    def decorate(function: Callable[_P, Awaitable[_R]]) -> Callable[_P, Awaitable[_R]]:
        @wraps(function)
        async def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            if not fresh and _reporter.get() is not None:
                return await function(*args, **kwargs)
            token = _reporter.set(ProgressReporter())
            try:
                return await function(*args, **kwargs)
            finally:
                _reporter.reset(token)

        return wrapped

    return decorate


async def report_progress(ctx: Context, message: str) -> None:
    """Send a message without an estimated total; the SDK handles opt-in clients."""
    reporter = _reporter.get()
    if reporter is None:
        reporter = ProgressReporter()
    await reporter.report(ctx, message)
