"""Versioned, durable graph-analysis policy."""

import hashlib
import os

ANALYZER_VERSION = 2


def library_analysis(value=None):
    mode = value if value is not None else os.environ.get("GRAPH_LIBRARY_ANALYSIS", "summary")
    if mode not in {"summary", "full"}:
        raise ValueError("GRAPH_LIBRARY_ANALYSIS must be summary or full")
    return mode


# Exact UTF-8 response hashes of inspected standalone distributions. Keep in sync with library.cjs.
LIBRARIES = {
    "f76dd498a673f19070ba71cb25c10f886b12ae3fb0fe2da7ee2ad97bb2b7c655": "AngularJS 1.7.7",
    "3691c923ea593c1f7b941443ee06a35ca0c3fdff54c9eaeb276fa4c42289ded5": "React development",
    "2e10ae11b803fd7adf1ba2fa497d97797b803efdcd54de28967555ea1916cb54": "React DOM development",
}


def recognized_library(source):
    return LIBRARIES.get(hashlib.sha256(source.encode()).hexdigest())
