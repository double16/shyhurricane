from dataclasses import fields
from pathlib import Path

import pytest
import yaml

from shyhurricane.graph.config import GraphTimeouts, graph_timeouts
from shyhurricane.graph.database import GraphStore
from shyhurricane.server_config import ServerConfig


@pytest.fixture(autouse=True)
def clear_timeouts(monkeypatch):
    for field in fields(GraphTimeouts):
        monkeypatch.delenv(f"NEO4J_{field.name.upper()}_TIMEOUT_SECONDS", raising=False)


def test_defaults_and_compose_forwarding():
    assert graph_timeouts() == GraphTimeouts(30, 30, 180, 15, 120)
    for name in ("docker-compose.yml", "docker-compose.dev.yml"):
        services = yaml.safe_load(Path(name).read_text())["services"]
        assert services["graph"]["environment"]["NEO4J_server_memory_pagecache_size"] == "${NEO4J_PAGECACHE_SIZE:-1g}"
        for field in fields(GraphTimeouts):
            variable = f"NEO4J_{field.name.upper()}_TIMEOUT_SECONDS"
            assert services["mcp"]["environment"][variable] == f"${{{variable}:-{int(field.default)}}}"


@pytest.mark.parametrize("field", fields(GraphTimeouts))
def test_override_is_shared_with_store_and_startup_validation(monkeypatch, field):
    monkeypatch.setenv(f"NEO4J_{field.name.upper()}_TIMEOUT_SECONDS", "2.5")
    ServerConfig()
    assert getattr(GraphStore("bolt://localhost:7687").timeouts, field.name) == 2.5


@pytest.mark.parametrize("field", fields(GraphTimeouts))
@pytest.mark.parametrize("value", ["", "bad", "0", "-1", "inf", "nan"])
def test_invalid_budget_fails_before_services_start(monkeypatch, field, value):
    variable = f"NEO4J_{field.name.upper()}_TIMEOUT_SECONDS"
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable):
        ServerConfig()
    with pytest.raises(ValueError, match=variable):
        GraphStore("bolt://localhost:7687")
