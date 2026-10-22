"""Bounded, monitor-owned sampling of optional Qdrant statistics."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Sample:
    value: Any = None
    sampled_at: float | None = None
    retry_at: float = 0
    failed: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class MonitorQdrantCache:
    """Cache complete samples; failed refreshes retain the last successful value."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.samples: dict[str, Sample] = {}

    async def get(self, key: str, load: Callable[[], Awaitable[Any]], interval: float, default: Any) -> Any:
        sample = self.samples.setdefault(key, Sample())
        async with sample.lock:
            if self.clock() >= sample.retry_at:
                started = self.clock()
                try:
                    async with asyncio.timeout(10):
                        value = await load()
                except Exception:
                    sample.failed = True
                    sample.retry_at = self.clock() + 60
                    logger.debug("Qdrant monitor refresh failed operation=%s elapsed=%.3fs",
                                 key, self.clock() - started, exc_info=True)
                else:
                    sample.value = value
                    sample.sampled_at = self.clock()
                    sample.retry_at = sample.sampled_at + interval
                    sample.failed = False
        return default if sample.sampled_at is None else sample.value

    def freshness(self) -> dict[str, dict]:
        return {
            key: {
                "age_seconds": None if sample.sampled_at is None else max(0, self.clock() - sample.sampled_at),
                "status": "unavailable" if sample.sampled_at is None else "stale" if sample.failed else "cached",
            }
            for key, sample in self.samples.items()
        }


async def bounded_count(store) -> int:
    """Use the store's existing async client with a per-request deadline."""
    async with asyncio.timeout(5):
        return await store.count_documents_async()


async def bounded_collection_count(client, collection: str) -> int:
    """Count a primary collection independently of initialized retrieval stores."""
    async with asyncio.timeout(5):
        if not await client.collection_exists(collection_name=collection):
            return 0
        return (await client.count(collection_name=collection, exact=True, timeout=5)).count
