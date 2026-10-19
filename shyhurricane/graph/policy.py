"""Versioned, durable graph-analysis policy."""

import os

ANALYZER_VERSION = 4


def library_analysis(value=None):
    mode = value if value is not None else os.environ.get("GRAPH_LIBRARY_ANALYSIS", "summary")
    if mode not in {"summary", "full"}:
        raise ValueError("GRAPH_LIBRARY_ANALYSIS must be summary or full")
    return mode
