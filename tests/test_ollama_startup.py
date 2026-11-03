"""Offline regression tests for startup model preparation."""
from unittest.mock import MagicMock

import pytest

from shyhurricane.generator_config import GeneratorConfig


@pytest.fixture(autouse=True)
def offline_ollama_preparation():
    """Exercise real preparation here; individual tests mock its network boundary."""


@pytest.fixture
def installed_models(monkeypatch):
    get = MagicMock()
    get.return_value.__enter__.return_value.json.return_value = {"models": []}
    monkeypatch.setattr("shyhurricane.generator_config.requests.get", get)
    return get


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
def test_prepare_unique_models(monkeypatch, supported, installed_models):
    pulls = []
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: supported)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: pulls.append(model))
    GeneratorConfig(ollama_model="nomic-embed-text:latest").prepare_ollama_models()
    expected = {"nomic-embed-text:latest"}
    if supported:
        expected.add("unclemusclez/jina-embeddings-v2-base-code:latest")
    assert pulls == sorted(expected)


def test_other_provider_does_not_pull(monkeypatch, installed_models):
    pull = MagicMock()
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", pull)
    GeneratorConfig(openai_model="test", ollama_model="unused").prepare_ollama_models()
    pull.assert_not_called()
    installed_models.assert_not_called()


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


@pytest.mark.parametrize(("required", "installed", "expected"), [
    ("llama3.2:3b", ["llama3.2:3b"], []),
    ("llama3.2:3b", ["llama3.2:latest"], ["llama3.2:3b"]),
    ("llama3.2", ["llama3.2:latest"], []),
    ("llama3.2", ["llama3.2:3b"], ["llama3.2:latest"]),
    ("registry.example.com:5000/team/model", [], ["registry.example.com:5000/team/model:latest"]),
])
def test_prepare_only_missing_models(monkeypatch, installed_models, required, installed, expected):
    installed_models.return_value.__enter__.return_value.json.return_value = {
        "models": [{"name": model} for model in installed],
    }
    pull = MagicMock()
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: False)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", pull)
    GeneratorConfig(ollama_host="example.com:11434", ollama_model=required).prepare_ollama_models()
    assert [call.args[0] for call in pull.call_args_list] == expected
    installed_models.assert_called_once_with("http://example.com:11434/api/tags", timeout=(10, 30))


@pytest.mark.parametrize("failure", ["http", "timeout", "malformed"])
def test_inventory_failure_stops_preparation(monkeypatch, installed_models, failure):
    response = installed_models.return_value.__enter__.return_value
    if failure == "http":
        response.raise_for_status.side_effect = RuntimeError("http")
    elif failure == "timeout":
        installed_models.side_effect = TimeoutError("timeout")
    else:
        response.json.return_value = {}
    pull = MagicMock()
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: False)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", pull)
    with pytest.raises(RuntimeError, match="Failed to list installed Ollama models"):
        GeneratorConfig(ollama_model="llama3.2:3b").prepare_ollama_models()
    pull.assert_not_called()
