"""Keep graph worker progress bounded and propagate cancellation into database reads."""

import asyncio
import logging
from contextlib import suppress

from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.query import GraphQuery
from shyhurricane.mcp_server.progress import report_progress

logger = logging.getLogger(__name__)


async def execute_graph(ctx, store, operation, *args, **kwargs):
    loop = asyncio.get_running_loop()
    updates = asyncio.Queue(maxsize=1)
    active = True

    def enqueue(message):
        if not active:
            return
        if updates.full():
            updates.get_nowait()
        updates.put_nowait(message)

    def progress(message):
        loop.call_soon_threadsafe(enqueue, message)

    inventory = operation == "endpoints" and kwargs.get("detail", "inventory") == "inventory"
    budget = QueryBudget(progress, seconds=30 if inventory else 120)
    service = GraphQuery(store, budget=budget)

    async def notify(message):
        try:
            async with asyncio.timeout(1):
                await report_progress(ctx, message)
        except Exception:
            logger.debug("Graph progress notification unavailable", exc_info=True)

    async def consume():
        while True:
            message = await updates.get()
            await notify(message)
            await asyncio.sleep(5)

    await notify(f"Graph query: starting {operation}")
    consumer = asyncio.create_task(consume())
    try:
        result = await asyncio.to_thread(getattr(service, operation), *args, **kwargs)
        logger.info("Graph query complete request=%s operation=%s reads=%s remaining_seconds=%.3f",
                    budget.request_id, operation, budget.reads, budget.remaining())
        await notify(f"Graph query: completed {operation}; {budget.reads} database reads")
        return result
    except asyncio.CancelledError:
        try:
            await asyncio.to_thread(budget.cancel)
        except Exception:
            logger.warning("Cannot terminate cancelled graph read", exc_info=True)
        raise
    finally:
        active = False
        consumer.cancel()
        with suppress(asyncio.CancelledError):
            await consumer
