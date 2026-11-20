"""Bounded recovery for temporary finding dependencies."""

import logging
import time

import httpx

logger = logging.getLogger(__name__)


def transient(error):
    """Inspect transport causes and narrowly recognized provider responses."""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, httpx.TransportError):
            return True
        status = getattr(error, "status_code", None)
        if status in (429, 502, 503, 504):
            return True
        message = str(error).lower()
        if status == 400 and "dial tcp 127.0.0.1:" in message and "operation timed out" in message:
            return True
        error = error.__cause__ or error.__context__
    return False


def run(operation, stop_event=None):
    """Retry outside the finding lock; cancellation leaves work unacknowledged."""
    for attempt in range(4):
        try:
            return operation()
        except Exception as error:
            if attempt == 3 or not transient(error):
                raise
            delay = (1, 3, 10)[attempt]
            logger.warning("Finding dependency retry attempt=%s type=%s delay=%s",
                           attempt + 1, type(error).__name__, delay)
            if stop_event is not None:
                if stop_event.wait(delay):
                    raise KeyboardInterrupt()
            else:
                time.sleep(delay)
