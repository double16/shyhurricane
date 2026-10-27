"""Keep graph worker progress bounded and propagate cancellation into database reads."""

import asyncio
import logging
import time
from contextlib import suppress

from shyhurricane.graph.budget import QueryBudget, page_budget, paging
from shyhurricane.graph.query import GraphQuery
from shyhurricane.mcp_server.progress import report_progress

logger = logging.getLogger(__name__)


async def execute_graph(ctx, store, operation, *args, artifact_db=None, budget=None, **kwargs):
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

    budget = budget or QueryBudget(progress)
    if paging.get():
        page_budget.set(budget)
    service = GraphQuery(store, budget=budget)

    async def notify(message):
        try:
            async with asyncio.timeout(min(1, max(0, budget.deadline - time.monotonic()))):
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
    worker = None
    try:
        def run():
            if artifact_db is None:
                return getattr(service, operation)(*args, **kwargs)
            from shyhurricane.graph.artifacts import ArtifactStore

            artifacts = ArtifactStore(artifact_db, readonly=True, budget=budget)
            try:
                service.artifacts = artifacts
                result = getattr(service, operation)(*args, **kwargs)
                if isinstance(result, dict):
                    try:
                        if "coverage" not in result:
                            result["coverage"] = artifacts.manifest.coverage(
                                scope=args[0] if args and operation in {"endpoints", "elements", "paths"} else None,
                                historical=kwargs.get("historical", False), as_of=kwargs.get("as_of"),
                            )
                        if "omitted_regions" not in result:
                            result["omitted_regions"] = (service.omitted_regions(args[0])
                                if args and operation in {"endpoints", "elements", "paths"} else [])
                    except TimeoutError:
                        result.setdefault("coverage", {"discovery": "unknown", "flow": "unknown"})
                        result.setdefault("omitted_regions", [])
                        result.setdefault("analysis_gaps", []).append("Graph metadata exceeded the query budget")
                        result["retrieval_truncated"] = True
                        reasons = result.setdefault("truncation_reasons", [])
                        if "time_limit" not in reasons:
                            reasons.append("time_limit")
                return result
            finally:
                artifacts.close()
        worker = asyncio.create_task(asyncio.to_thread(run))
        try:
            result = await asyncio.wait_for(asyncio.shield(worker), max(0, budget.deadline - time.monotonic()))
        except TimeoutError:
            async with asyncio.timeout(5):
                await asyncio.to_thread(budget.cancel)
                result = await asyncio.shield(worker)
        logger.info("Graph query complete request=%s operation=%s reads=%s remaining_seconds=%.3f",
                    budget.request_id, operation, budget.reads, budget.remaining())
        await notify(f"Graph query: completed {operation}; {budget.reads} database reads")
        return result
    except asyncio.CancelledError:
        with suppress(Exception):
            async with asyncio.timeout(5):
                with suppress(Exception):
                    await asyncio.to_thread(budget.cancel)
                if worker is not None:
                    await asyncio.shield(worker)
        raise
    finally:
        active = False
        consumer.cancel()
        with suppress(asyncio.CancelledError):
            await consumer
