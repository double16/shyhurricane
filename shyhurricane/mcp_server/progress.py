"""Report client progress with counters scoped to an inbound tool request."""

import asyncio
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from functools import wraps
from typing import ParamSpec, TypeVar

from mcp.server.mcpserver import Context

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ProgressReporter:
    def __init__(self) -> None:
        self.count = 0
        self.lock = asyncio.Lock()

    async def report(self, ctx: Context, message: str) -> None:
        async with self.lock:
            self.count += 1
            await ctx.report_progress(self.count, message=message)


_reporter: ContextVar[ProgressReporter | None] = ContextVar("shyhurricane_progress", default=None)


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
