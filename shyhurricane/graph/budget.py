"""One cancellable wall-clock budget and progress channel per graph request."""

import logging
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from uuid import uuid4

from neo4j.exceptions import ConnectionAcquisitionTimeoutError

from shyhurricane.graph.config import graph_timeouts

logger = logging.getLogger(__name__)
current_budget = ContextVar("graph_read_budget", default=None)
page_budget = ContextVar("graph_page_budget", default=None)
paging = ContextVar("graph_paging", default=False)
QUERY_SECONDS = 120


class QueryBudget:
    def __init__(self, progress=None, *, seconds=QUERY_SECONDS):
        self.started = time.monotonic()
        self.deadline = self.started + seconds
        self.cancelled = threading.Event()
        self.progress = progress or (lambda message: None)
        self.lock = threading.Lock()
        self.request_id = uuid4().hex
        self.interrupts = set()
        self.terminate = None
        self.reads = 0
        self.checkpointing = 0

    def cancel(self):
        with self.lock:
            self.cancelled.set()
            terminate = self.terminate
            for interrupt in self.interrupts:
                interrupt()
        if terminate is not None:
            terminate()

    def remaining(self):
        reserve = 0 if self.checkpointing else 5
        return 0 if self.cancelled.is_set() else max(0, self.deadline - time.monotonic() - reserve)

    def check(self):
        if self.remaining() <= 0:
            raise TimeoutError("Graph query budget reached")

    @contextmanager
    def checkpoint(self):
        """Use the response reserve without extending the request deadline."""
        self.checkpointing += 1
        try:
            yield
        finally:
            self.checkpointing -= 1

    def read(self, store, statement, *, timeout=None, **parameters):
        remaining = self.remaining()
        if remaining < 0.001:
            raise TimeoutError("Graph query budget reached")
        token = current_budget.set(self)
        before = time.monotonic()
        self.reads += 1
        stage = statement.split("*/", 1)[0].removeprefix("/* ") if statement.startswith("/*") else "graph read"
        try:
            rows = store.read(
                statement, timeout=min(graph_timeouts().read, remaining, timeout or remaining), **parameters,
            )
            self.progress(f"Graph query: {stage}; read {self.reads}, returned {len(rows)} records")
            return rows
        except ConnectionAcquisitionTimeoutError as error:
            raise TimeoutError("Graph connection-pool wait exceeded its budget") from error
        finally:
            current_budget.reset(token)
            logger.debug("Graph query request=%s stage=%s read=%s seconds=%.3f remaining_seconds=%.3f",
                         self.request_id, stage, self.reads,
                         time.monotonic() - before, self.remaining())
