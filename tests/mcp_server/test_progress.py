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


@pytest.mark.asyncio
async def test_idle_deadlines_reset_and_recheck_under_lock(monkeypatch):
    from shyhurricane.mcp_server import progress

    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(progress, "time", SimpleNamespace(monotonic=lambda: clock.now))
    reporter = progress.ProgressReporter()
    ctx = SimpleNamespace(report_progress=AsyncMock())
    waits = []

    async def sleep(delay):
        waits.append(delay)
        if len(waits) == 1:
            clock.now = 20.0
        elif len(waits) == 2:
            # An informative update wins the race with a waking heartbeat.
            clock.now = 40.0
            await reporter.report(ctx, "Found result")
        elif len(waits) == 3:
            clock.now = 60.0
        else:
            raise asyncio.CancelledError

    monkeypatch.setattr(progress, "asyncio", SimpleNamespace(sleep=sleep))
    with pytest.raises(asyncio.CancelledError):
        await reporter.heartbeat(ctx, "Still running")
    assert waits == [20.0, 20.0, 20.0, 20.0]
    assert [(call.args[0], call.kwargs["message"]) for call in ctx.report_progress.await_args_list] == [
        (1, "Still running"), (2, "Found result"), (3, "Still running")
    ]


@pytest.mark.asyncio
async def test_failed_heartbeat_backs_off_without_holding_lock(monkeypatch, caplog):
    from shyhurricane.mcp_server import progress

    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(progress, "time", SimpleNamespace(monotonic=lambda: clock.now))
    reporter = progress.ProgressReporter()
    ctx = SimpleNamespace(report_progress=AsyncMock(side_effect=RuntimeError("disconnected")))
    waits = []

    async def sleep(delay):
        waits.append(delay)
        assert not reporter.lock.locked()
        if len(waits) == 1:
            clock.now = 20.0
        else:
            assert reporter.last_progress == 0.0
            raise asyncio.CancelledError

    monkeypatch.setattr(progress, "asyncio", SimpleNamespace(sleep=sleep))
    with pytest.raises(asyncio.CancelledError):
        await reporter.heartbeat(ctx, "Still running")
    assert waits == [20.0, 20.0]
    assert "Failed to send idle progress" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "error", "cancel", "timeout"])
async def test_idle_task_is_cleaned_up(monkeypatch, outcome):
    from shyhurricane.mcp_server import progress

    entered = asyncio.Event()
    stopped = asyncio.Event()

    async def heartbeat(self, ctx, message):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    monkeypatch.setattr(progress.ProgressReporter, "heartbeat", heartbeat)

    @progress_scope(fresh=True)
    async def request():
        async with progress.idle_progress(SimpleNamespace(), "port_scan"):
            await entered.wait()
            if outcome == "error":
                raise ValueError("tool failure")
            if outcome == "cancel":
                raise asyncio.CancelledError
            if outcome == "timeout":
                async with asyncio.timeout(0):
                    await asyncio.sleep(0)
            return "result"

    if outcome == "success":
        assert await request() == "result"
    else:
        failure = {"error": ValueError, "cancel": asyncio.CancelledError, "timeout": TimeoutError}[outcome]
        with pytest.raises(failure):
            await request()
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_excluded_and_unscoped_calls_have_no_timer(monkeypatch):
    from shyhurricane.mcp_server import progress

    heartbeat = AsyncMock()
    monkeypatch.setattr(progress.ProgressReporter, "heartbeat", heartbeat)
    async with progress.idle_progress(SimpleNamespace(), "port_scan"):
        pass

    @progress_scope(fresh=True)
    async def request():
        async with progress.idle_progress(SimpleNamespace(), "find_wordlists"):
            await asyncio.sleep(0)

    await request()
    heartbeat.assert_not_awaited()


@pytest.mark.asyncio
async def test_quick_eligible_call_has_no_synthetic_update():
    from shyhurricane.mcp_server.progress import idle_progress

    ctx = SimpleNamespace(report_progress=AsyncMock())

    @progress_scope(fresh=True)
    async def request():
        async with idle_progress(ctx, "index_http_url"):
            await asyncio.sleep(0)
            return "done"

    assert await request() == "done"
    ctx.report_progress.assert_not_awaited()


@pytest.mark.asyncio
async def test_concurrent_idle_requests_share_nested_counters_only(monkeypatch):
    from shyhurricane.mcp_server import progress

    monkeypatch.setattr(progress, "PROGRESS_INTERVAL_SECONDS", 0.01)

    @progress_scope()
    async def nested(ctx):
        await report_progress(ctx, "nested")

    @progress_scope(fresh=True)
    async def request():
        received = asyncio.Event()
        updates = []

        async def send(value, *, message):
            updates.append((value, message))
            if message.endswith("is still running"):
                received.set()

        ctx = SimpleNamespace(report_progress=send)
        async with progress.idle_progress(ctx, "port_scan"):
            await nested(ctx)
            await asyncio.wait_for(received.wait(), timeout=2)
        return updates

    results = await asyncio.gather(request(), request())
    assert results == [[(1, "nested"), (2, "port_scan is still running")]] * 2
