import logging
import multiprocessing
import threading
from collections.abc import Callable

from httpx import TransportError
from neo4j.exceptions import Neo4jError, ServiceUnavailable, SessionExpired
from qdrant_client import QdrantClient
from qdrant_client.http.exceptions import ResponseHandlingException, UnexpectedResponse

logger = logging.getLogger(__name__)

DATABASE_HEALTH_ERRORS = (
    Neo4jError,
    ServiceUnavailable,
    SessionExpired,
    ResponseHandlingException,
    UnexpectedResponse,
    TransportError,
    OSError,
)


def _log_database_health_failure(database: str, error: Exception) -> None:
    summary = " ".join(str(error).split())
    logger.warning("%s health check failed (%s): %s", database, type(error).__name__, summary)


class HealthMonitor:
    """Periodically checks indexing dependencies and exposes shared readiness."""

    def __init__(
        self,
        qdrant_probe: Callable[[], object],
        llm_probe: Callable[[], object],
        interval: float = 10,
        neo4j_probe: Callable[[], object] | None = None,
        disk_guard=None,
    ):
        self.disk_guard = disk_guard
        self.ready = multiprocessing.Event()
        self._qdrant_probe = qdrant_probe
        self._llm_probe = llm_probe
        self._neo4j_probe = neo4j_probe
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="health-monitor", daemon=True)
        self._last_state = None
        self.qdrant_healthy: bool | None = None
        self.llm_healthy: bool | None = None
        self.neo4j_healthy: bool | None = None

    def start(self):
        self._thread.start()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=self._interval + 1)

    def check(self) -> bool:
        try:
            qdrant_healthy = bool(self._qdrant_probe())
        except DATABASE_HEALTH_ERRORS as error:
            _log_database_health_failure("Qdrant", error)
            qdrant_healthy = False
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
        try:
            self.neo4j_healthy = bool(self._neo4j_probe()) if self._neo4j_probe is not None else True
        except DATABASE_HEALTH_ERRORS as error:
            _log_database_health_failure("Neo4j", error)
            self.neo4j_healthy = False
        except Exception:
            logger.warning("Neo4j health check failed", exc_info=True)
            self.neo4j_healthy = False
        disk_healthy = self.disk_guard.check() if self.disk_guard is not None else True
        healthy = qdrant_healthy and llm_healthy and self.neo4j_healthy and disk_healthy
        if healthy:
            self.ready.set()
        else:
            self.ready.clear()
        if healthy != self._last_state:
            logger.info("Indexing readiness is %s", "healthy" if healthy else "unhealthy")
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
                self.neo4j_healthy = False
                self.ready.clear()
            self._stop.wait(self._interval)


def qdrant_probe(host: str, port: int) -> bool:
    probe_client = QdrantClient(host=host, port=port, timeout=5)
    try:
        probe_client.get_collections()
    finally:
        probe_client.close()
    return True
