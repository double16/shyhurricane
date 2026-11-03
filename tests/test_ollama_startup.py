"""Offline regression tests for startup model preparation."""
from unittest.mock import MagicMock

import pytest

from shyhurricane.generator_config import GeneratorConfig


@pytest.fixture(autouse=True)
def offline_ollama_preparation():
    """Exercise real preparation here; individual tests mock its network boundary."""


@pytest.mark.parametrize("model", ["llama3.2:3b", "llama3.2", "namespace/model:custom"])
def test_pull_preserves_identifier(monkeypatch, model):
    post = MagicMock()
    post.return_value.__enter__.return_value.json.return_value = {}
    monkeypatch.setattr("shyhurricane.generator_config.requests.post", post)
    GeneratorConfig().ollama_pull(model)
    assert post.call_args.kwargs == {
        "json": {"model": model, "stream": False}, "timeout": (10, 600),
    }


@pytest.mark.parametrize("failure", ["http", "body", "timeout"])
def test_pull_failures_identify_model(monkeypatch, failure):
    post = MagicMock()
    response = post.return_value.__enter__.return_value
    response.json.return_value = {"error": "failed"} if failure == "body" else {}
    if failure == "http":
        response.raise_for_status.side_effect = RuntimeError("http")
    if failure == "timeout":
        post.side_effect = TimeoutError("timeout")
    monkeypatch.setattr("shyhurricane.generator_config.requests.post", post)
    with pytest.raises(RuntimeError, match="llama3.2:3b"):
        GeneratorConfig().ollama_pull("llama3.2:3b")


@pytest.mark.parametrize("supported", [True, False])
def test_prepare_unique_models(monkeypatch, supported):
    pulls = []
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: supported)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: pulls.append(model))
    GeneratorConfig(ollama_model="nomic-embed-text:latest").prepare_ollama_models()
    expected = {"nomic-embed-text:latest"}
    if supported:
        expected.add("unclemusclez/jina-embeddings-v2-base-code:latest")
    assert pulls == sorted(expected)


def test_other_provider_does_not_pull(monkeypatch):
    pull = MagicMock()
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", pull)
    GeneratorConfig(openai_model="test", ollama_model="unused").prepare_ollama_models()
    pull.assert_not_called()


@pytest.mark.asyncio
async def test_failed_preparation_stops_startup(monkeypatch):
    import shyhurricane.mcp_server.server_context as context

    config = GeneratorConfig(ollama_model="llama3.2:3b")
    prepare = MagicMock(side_effect=RuntimeError("pull failed"))
    monkeypatch.setattr(context, "_server_context", None)
    monkeypatch.setattr(context, "get_generator_config", lambda: config)
    monkeypatch.setattr(GeneratorConfig, "prepare_ollama_models", prepare)
    configure = MagicMock()
    monkeypatch.setattr(context, "configure_data_dir", configure)
    with pytest.raises(RuntimeError, match="pull failed"):
        await context.get_server_context()
    prepare.assert_called_once()
    configure.assert_not_called()
