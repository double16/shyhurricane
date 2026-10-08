import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shyhurricane.mcp_server.progress import progress_scope, report_progress


@pytest.mark.asyncio
async def test_nested_operations_share_counter_and_concurrent_requests_are_isolated():
    @progress_scope()
    async def nested(ctx):
        await report_progress(ctx, "nested")

    @progress_scope(fresh=True)
    async def request(ctx):
        await report_progress(ctx, "start")
        await asyncio.sleep(0)
        await nested(ctx)
        await report_progress(ctx, "end")

    contexts = [SimpleNamespace(report_progress=AsyncMock()) for _ in range(2)]
    await asyncio.gather(*(request(ctx) for ctx in contexts))
    for ctx in contexts:
        assert [(call.args[0], call.kwargs) for call in ctx.report_progress.await_args_list] == [
            (1, {"message": "start"}),
            (2, {"message": "nested"}),
            (3, {"message": "end"}),
        ]
        await request(ctx)
        assert ctx.report_progress.await_args_list[3].args == (1,)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
async def test_failed_request_discards_counter_and_propagates_error(failure):
    ctx = SimpleNamespace(report_progress=AsyncMock(side_effect=failure))

    @progress_scope()
    async def request():
        await report_progress(ctx, "update")

    with pytest.raises(failure):
        await request()
    ctx.report_progress.side_effect = None
    await request()
    assert [call.args[0] for call in ctx.report_progress.await_args_list] == [1, 1]


@pytest.mark.asyncio
async def test_unscoped_helper_and_nested_fresh_request():
    ctx = SimpleNamespace(report_progress=AsyncMock())

    @progress_scope(fresh=True)
    async def inner():
        await report_progress(ctx, "inner")

    @progress_scope()
    async def outer():
        await report_progress(ctx, "before")
        await inner()
        await report_progress(ctx, "after")

    await report_progress(ctx, "unscoped")
    await outer()
    assert [call.args[0] for call in ctx.report_progress.await_args_list] == [1, 1, 1, 2]


@pytest.mark.asyncio
async def test_concurrent_notifications_are_sent_in_counter_order():
    messages = []

    async def send(progress, *, message):
        await asyncio.sleep(0)
        messages.append((progress, message))

    ctx = SimpleNamespace(report_progress=send)

    @progress_scope()
    async def request():
        await asyncio.gather(*(report_progress(ctx, str(index)) for index in range(3)))

    await request()
    assert messages == [(1, "0"), (2, "1"), (3, "2")]
