import logging
import multiprocessing
import threading
from collections.abc import Callable

from qdrant_client import QdrantClient

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Periodically checks indexing dependencies and exposes shared readiness."""

    def __init__(self, qdrant_probe: Callable[[], object], llm_probe: Callable[[], object], interval: float = 10):
        self.ready = multiprocessing.Event()
        self._qdrant_probe = qdrant_probe
        self._llm_probe = llm_probe
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="health-monitor", daemon=True)
        self._last_state = None
        self.qdrant_healthy: bool | None = None
        self.llm_healthy: bool | None = None

    def start(self):
        self._thread.start()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=self._interval + 1)

    def check(self) -> bool:
        try:
            qdrant_healthy = bool(self._qdrant_probe())
        except Exception:
            logger.warning("Qdrant health check failed", exc_info=True)
            qdrant_healthy = False
        self.qdrant_healthy = qdrant_healthy
        try:
            llm_healthy = bool(self._llm_probe())
        except Exception:
            logger.warning("LLM health check failed", exc_info=True)
            llm_healthy = False
        self.llm_healthy = llm_healthy
        healthy = qdrant_healthy and llm_healthy
        if healthy:
            self.ready.set()
        else:
            self.ready.clear()
        if healthy != self._last_state:
            logger.info("Indexing dependencies are %s", "healthy" if healthy else "unhealthy")
            self._last_state = healthy
        return healthy

    def _run(self):
        while not self._stop.is_set():
            try:
                self.check()
            except Exception:
                logger.warning("Health monitor check failed", exc_info=True)
                self.qdrant_healthy = False
                self.llm_healthy = False
                self.ready.clear()
            self._stop.wait(self._interval)


def qdrant_probe(host: str, port: int) -> bool:
    probe_client = QdrantClient(host=host, port=port)
    try:
        probe_client.get_collections()
    finally:
        probe_client.close()
    return True