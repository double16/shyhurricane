"""Lazy, serialized query embedding for saved findings."""

import asyncio
import threading

from shyhurricane.doc_type_model_map import get_model_for_doc_type


class FindingSemanticSearch:
    """Share one provider embedder without blocking the request event loop."""

    def __init__(self, config_factory):
        self.config_factory = config_factory
        self.embedder = None
        self.lock = threading.Lock()

    def _ensure_embedder(self):
        if self.embedder is None:
            embedder = self.config_factory().create_text_embedder(get_model_for_doc_type("finding").model_config)
            if hasattr(embedder, "warm_up"):
                embedder.warm_up()
            self.embedder = embedder

    def _prepare(self):
        with self.lock:
            self._ensure_embedder()

    async def prepare(self):
        await asyncio.to_thread(self._prepare)

    def _embed(self, query: str) -> list[float]:
        # The thread owns the lock even if its awaiting request is cancelled.
        with self.lock:
            self._ensure_embedder()
            return self.embedder.run(text=query)["embedding"]

    async def embed(self, query: str) -> list[float]:
        return await asyncio.to_thread(self._embed, query)
