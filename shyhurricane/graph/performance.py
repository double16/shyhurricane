"""Bounded operation summaries with aggregate phase timings and content-free counters."""

import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path

_active = ContextVar("graph_performance", default=None)
_child_totals = {}
_child_next = 0.0


def _aggregate_child(event, state, seconds, failed):
    global _child_next
    key = event if event in _child_totals or len(_child_totals) < 7 else "other"
    value = _child_totals.setdefault(key, {"operations": 0, "failed_operations": 0,
                                          "total_seconds": 0.0, "max_seconds": 0.0,
                                          "counts": {}, "phase_seconds": {}})
    value["operations"] += 1
    value["failed_operations"] += int(failed)
    value["total_seconds"] += seconds
    value["max_seconds"] = max(value["max_seconds"], seconds)
    for field, source in (("counts", "counts"), ("phase_seconds", "phases")):
        for name, number in state[source].items():
            value[field][name] = value[field].get(name, 0) + number
    if time.monotonic() >= _child_next:
        _child_next = time.monotonic() + 30
        flush_child_metrics(final=False)


def flush_child_metrics(*, final=True):
    """Forward aggregate parser measurements through its existing bounded diagnostic tail."""
    global _child_next
    values = dict(_child_totals)
    if final:
        _child_totals.clear()
        _child_next = 0.0
    path = os.environ.get("_SHYHURRICANE_PARSE_DIAGNOSTICS")
    if path and values:
        try:
            with Path(path).open("a") as stream:
                for event, value in values.items():
                    stream.write(json.dumps({"stage": "performance", "event": event,
                                             "timestamp": time.time(), "cumulative": True,
                                             "final": final, **value}, sort_keys=True) + "\n")
        except OSError:
            # Observability must not turn a completed analysis into a failed capture.
            pass


def count(name, value=1):
    state = _active.get()
    if state is not None:
        state["counts"][name] = state["counts"].get(name, 0) + value
        state["work"] = state["work"] or value != 0


def label(**values):
    state = _active.get()
    if state is not None:
        state["labels"].update(values)
        state["work"] = True


def elapsed(name, seconds):
    state = _active.get()
    if state is not None:
        state["phases"][name] = state["phases"].get(name, 0.0) + max(0.0, seconds)


@contextmanager
def phase(name):
    if _active.get() is None:
        yield
        return
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed(name, time.perf_counter() - started)


def timed(name):
    """Time a leaf operation within an active summary, without logging per record."""
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if _active.get() is None:
                return function(*args, **kwargs)
            with phase(name):
                return function(*args, **kwargs)
        return wrapped
    return decorate


@contextmanager
def commit_timing(connection):
    """Measure the caller-owned SQLite commit, excluding the transaction body."""
    committing = None
    try:
        with connection:
            yield
            committing = time.perf_counter()
    finally:
        if committing is not None:
            elapsed("sqlite_commit", time.perf_counter() - committing)


def measured(event, logger, *, level=logging.INFO, quiet=False, minimum_bytes=None, summary_interval=None):
    """Emit one summary per operation; idle polling can opt out of successful logs.

    Labels must be internal stage names, opaque IDs, or booleans, never request content.
    Counts describe attempted work when outcome is error; they are not durable totals.
    """
    def decorate(function):
        totals = {}
        totals_lock = threading.Lock()

        def aggregate(state, seconds):
            now = time.monotonic()
            with totals_lock:
                if not totals:
                    totals.update(started=now, operations=0, total_seconds=0.0, max_seconds=0.0,
                                  counts={}, phase_seconds={})
                totals["operations"] += 1
                totals["total_seconds"] += seconds
                totals["max_seconds"] = max(totals["max_seconds"], seconds)
                for destination, source in (("counts", "counts"), ("phase_seconds", "phases")):
                    for name, value in state[source].items():
                        totals[destination][name] = totals[destination].get(name, 0) + value
                if now - totals["started"] >= summary_interval:
                    result = {"event": event, "outcome": "complete", "aggregate": True,
                              "window_seconds": now - totals["started"],
                              **{key: value for key, value in totals.items() if key != "started"}}
                    totals.clear()
                    logger.info("Graph performance %s", json.dumps(result, sort_keys=True))

        @wraps(function)
        def wrapped(*args, **kwargs):
            child_channel = os.environ.get("_SHYHURRICANE_PARSE_DIAGNOSTICS")
            enabled_level = logging.WARNING if summary_interval is not None else level
            if not logger.isEnabledFor(enabled_level) and not child_channel:
                return function(*args, **kwargs)
            state = {"counts": {}, "phases": {}, "labels": {}, "work": False}
            token = _active.set(state)
            started = time.perf_counter()
            outcome, error_type = "complete", None
            try:
                return function(*args, **kwargs)
            except BaseException as error:
                outcome, error_type = "error", type(error).__name__
                raise
            finally:
                _active.reset(token)
                seconds = max(0.0, time.perf_counter() - started)
                output_level = level
                if summary_interval is not None and not child_channel:
                    if error_type is None:
                        aggregate(state, seconds)
                        output_level = logging.DEBUG
                    else:
                        output_level = logging.WARNING
                if minimum_bytes is not None and error_type is None and max(
                    state["counts"].get("logical_bytes", 0), state["counts"].get("decoded_bytes", 0)
                ) < minimum_bytes:
                    output_level = logging.DEBUG
                if not quiet or state["work"] or error_type is not None:
                    if child_channel and output_level >= logging.INFO:
                        _aggregate_child(event, state, seconds, error_type is not None)
                if logger.isEnabledFor(output_level) and (not quiet or state["work"] or error_type is not None):
                    result = {"event": event, "outcome": outcome, "elapsed_seconds": seconds,
                              "phase_seconds": state["phases"], **state["counts"], **state["labels"]}
                    if error_type is not None:
                        result["error_type"] = error_type
                    if seconds > 0:
                        for name in ("records", "returned_records", "stored_bytes", "copy_bytes"):
                            if name in state["counts"]:
                                result[name + "_per_second"] = state["counts"][name] / seconds
                    logger.log(output_level, "Graph performance %s", json.dumps(result, sort_keys=True))
        return wrapped
    return decorate
