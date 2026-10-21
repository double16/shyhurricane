import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from shyhurricane.mcp_server import graph_execution, progress


async def test_worker_progress_is_coalesced_and_completion_is_reported(monkeypatch):
    received = []

    class Service:
        def __init__(self, store, *, budget):
            self.budget = budget

        def elements(self, scope):
            for index in range(100):
                self.budget.progress(f"batch {index}")
            return {"results": [scope]}

    monkeypatch.setattr(graph_execution, "GraphQuery", Service)
    monkeypatch.setattr(graph_execution, "report_progress", AsyncMock(side_effect=lambda ctx, text: received.append(text)))
    assert await graph_execution.execute_graph(None, object(), "elements", "example.com") == {"results": ["example.com"]}
    assert received[0].startswith("Graph query: starting")
    assert received[-1].startswith("Graph query: completed")
    assert len(received) <= 3


async def test_progress_failure_does_not_fail_query(monkeypatch):
    service = SimpleNamespace(evidence=lambda value: value)
    monkeypatch.setattr(graph_execution, "GraphQuery", lambda *args, **kwargs: service)
    monkeypatch.setattr(graph_execution, "report_progress", AsyncMock(side_effect=RuntimeError("no token")))
    assert await graph_execution.execute_graph(None, object(), "evidence", "proof") == "proof"


@pytest.mark.parametrize("cancel_fails", [False, True])
async def test_cancellation_stops_worker_and_cleans_up_progress(monkeypatch, cancel_fails):
    started = threading.Event()
    finished = threading.Event()
    budgets = []

    class Service:
        def __init__(self, store, *, budget):
            self.budget = budget
            budgets.append(budget)

        def elements(self, value):
            started.set()
            self.budget.cancelled.wait(2)
            finished.set()
            return value

    monkeypatch.setattr(graph_execution, "GraphQuery", Service)
    monkeypatch.setattr(graph_execution, "report_progress", AsyncMock())
    task = asyncio.create_task(graph_execution.execute_graph(None, object(), "elements", "example.com"))
    assert await asyncio.to_thread(started.wait, 2)
    if cancel_fails:
        budgets[0].terminate = MagicMock(side_effect=RuntimeError("offline"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert budgets[0].cancelled.is_set()
    assert await asyncio.to_thread(finished.wait, 2)


@pytest.mark.parametrize("tool", sorted(progress.GRAPH_TOOLS))
async def test_graph_tools_use_five_second_idle_progress(monkeypatch, tool):
    observed = []
    entered = asyncio.Event()

    async def heartbeat(self, ctx, message):
        observed.append(self.interval)
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(progress.ProgressReporter, "heartbeat", heartbeat)

    @progress.progress_scope(fresh=True)
    async def request():
        async with progress.idle_progress(SimpleNamespace(), tool):
            await entered.wait()

    await request()
    assert observed == [5]


async def test_fixed_deadline_is_not_extended_by_progress(monkeypatch):
    completed = threading.Event()
    budgets = []

    class Service:
        def __init__(self, store, *, budget):
            budgets.append(budget)
            self.budget = budget

        def elements(self, value):
            self.budget.cancelled.wait(2)
            completed.set()
            return value

    monkeypatch.setattr(graph_execution, "GraphQuery", Service)
    notify = AsyncMock()
    monkeypatch.setattr(graph_execution, "report_progress", notify)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await graph_execution.execute_graph(None, object(), "elements", "example.com")
    assert notify.await_count >= 1
    assert budgets[0].cancelled.is_set()
    assert await asyncio.to_thread(completed.wait, 2)


async def test_late_worker_updates_are_discarded(monkeypatch):
    callbacks = []

    class Service:
        def __init__(self, store, *, budget):
            callbacks.append(budget.progress)

        def evidence(self, value):
            return value

    monkeypatch.setattr(graph_execution, "GraphQuery", Service)
    notify = AsyncMock()
    monkeypatch.setattr(graph_execution, "report_progress", notify)
    await graph_execution.execute_graph(None, object(), "evidence", "proof")
    calls = notify.await_count
    callbacks[0]("too late")
    await asyncio.sleep(0)
    assert notify.await_count == calls


@pytest.mark.parametrize("arguments,seconds", [({}, 30), ({"detail": "inventory"}, 30), ({"detail": "summary"}, 120)])
async def test_endpoint_detail_selects_graph_budget(monkeypatch, arguments, seconds):
    budgets = []

    class Service:
        def __init__(self, store, *, budget):
            budgets.append(budget)

        def endpoints(self, scope, **kwargs):
            return {"results": []}

    monkeypatch.setattr(graph_execution, "GraphQuery", Service)
    monkeypatch.setattr(graph_execution, "report_progress", AsyncMock())
    await graph_execution.execute_graph(None, object(), "endpoints", "example.com", **arguments)
    assert budgets[0].deadline - budgets[0].started == seconds
