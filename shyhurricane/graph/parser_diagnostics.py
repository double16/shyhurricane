"""Small cross-process stage records for supervised graph extraction."""

import json
import os
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path


def remaining_seconds(default=240):
    deadline = os.environ.get("_SHYHURRICANE_PARSE_DEADLINE")
    return max(0.001, float(deadline) - time.monotonic()) if deadline else default


@contextmanager
def stage(name):
    path = os.environ.get("_SHYHURRICANE_PARSE_DIAGNOSTICS")
    started = time.monotonic()

    def report(state):
        if path:
            with Path(path).open("a") as stream:
                stream.write(json.dumps({"stage": name, "state": state,
                                         "seconds": round(time.monotonic() - started, 3)}) + "\n")

    report("started")
    try:
        yield
    finally:
        report("finished")


def measured(name):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with stage(name):
                return function(*args, **kwargs)
        return wrapped
    return decorate
