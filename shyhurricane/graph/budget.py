"""One cancellable wall-clock budget and progress channel per graph request."""

import logging
import threading
import time
from contextvars import ContextVar
from uuid import uuid4

from shyhurricane.graph.config import graph_timeouts

logger = logging.getLogger(__name__)
current_budget = ContextVar("graph_read_budget", default=None)
QUERY_SECONDS = 120


class QueryBudget:
    def __init__(self, progress=None):
        self.started = time.monotonic()
        self.deadline = self.started + QUERY_SECONDS
        self.cancelled = threading.Event()
        self.progress = progress or (lambda message: None)
        self.lock = threading.Lock()
        self.request_id = uuid4().hex
        self.terminate = None
        self.reads = 0

    def cancel(self):
        self.cancelled.set()
        with self.lock:
            terminate = self.terminate
        if terminate is not None:
            terminate()

    def remaining(self):
        return 0 if self.cancelled.is_set() else max(0, self.deadline - time.monotonic())

    def read(self, store, statement, *, timeout=None, **parameters):
        remaining = self.remaining()
        if remaining < 0.001:
            raise TimeoutError("Graph query budget reached")
        token = current_budget.set(self)
        before = time.monotonic()
        self.reads += 1
        stage = statement.split("*/", 1)[0].removeprefix("/* ") if statement.startswith("/*") else "graph read"
        try:
            rows = store.read(statement, timeout=min(graph_timeouts().read, remaining, timeout or remaining), **parameters)
            self.progress(f"Graph query: {stage}; read {self.reads}, returned {len(rows)} records")
            return rows
        finally:
            current_budget.reset(token)
            logger.debug("Graph query request=%s stage=%s read=%s seconds=%.3f remaining_seconds=%.3f",
                         self.request_id, stage, self.reads,
                         time.monotonic() - before, self.remaining())
