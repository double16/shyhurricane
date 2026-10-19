"""Validated transaction budgets shared by graph readers and workers."""

import math
import os
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class GraphTimeouts:
    read: float = 30.0
    control: float = 30.0
    write: float = 180.0
    health: float = 15.0
    schema: float = 120.0


def graph_timeouts() -> GraphTimeouts:
    values = {}
    for field in fields(GraphTimeouts):
        name = f"NEO4J_{field.name.upper()}_TIMEOUT_SECONDS"
        try:
            value = float(os.environ.get(name, field.default))
        except ValueError as error:
            raise ValueError(f"{name} must be finite and positive") from error
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be finite and positive")
        values[field.name] = value
    return GraphTimeouts(**values)
