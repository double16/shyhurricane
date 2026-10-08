import argparse
import importlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from haystack import Document
from haystack.dataclasses import ChatMessage
from openai import AuthenticationError

import shyhurricane.generator_config as generator_config
from shyhurricane.doc_type_model_map import ModelConfig
from shyhurricane.generator_config import ChatGeneratorCompatibilityWrapper, GeneratorConfig, safe_embedder


def test_google_retry_client_preserves_credentials_backoff_and_releases_original(monkeypatch):
    original = Mock()
    replacement = Mock()
    captured = {}

    def initialize(self, **kwargs):
        captured.update(kwargs)
        self._client = original

    client_factory = Mock(return_value=replacement)
    monkeypatch.setattr(generator_config.GoogleGenAIChatGenerator, "__init__", initialize)
    monkeypatch.setattr(generator_config, "Client", client_factory)
    key = generator_config.Secret.from_token("test-key")
    generator = generator_config.GoogleGenAIChatGeneratorWithRetry(api_key=key, model="gemini-test")
    assert captured == {"api_key": key, "model": "gemini-test"}
    assert client_factory.call_args.kwargs["api_key"] == "test-key"
    retry = client_factory.call_args.kwargs["http_options"].retry_options
    assert retry.attempts == 10
    assert retry.exp_base == 4.0
    original.close.assert_called_once_with()
    generator.close()
    replacement.close.assert_called_once_with()


def test_google_retry_client_releases_original_when_replacement_fails(monkeypatch):
    original = Mock()

    def initialize(self, **kwargs):
        self._client = original

    monkeypatch.setattr(generator_config.GoogleGenAIChatGenerator, "__init__", initialize)
    monkeypatch.setattr(generator_config, "Client", Mock(side_effect=RuntimeError("client failed")))
    with pytest.raises(RuntimeError, match="client failed"):
        generator_config.GoogleGenAIChatGeneratorWithRetry(api_key=generator_config.Secret.from_token("test-key"))
    original.close.assert_called_once_with()


def test_openai_generator_preserves_requests_and_reply_contract_with_mock_transport():
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "created": 0, "model": "gpt-test",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "answer"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        })

    generator = generator_config.OpenAIChatGenerator(
        api_key=generator_config.Secret.from_token("test-key"), model="gpt-test", max_retries=0,
        generation_kwargs={"temperature": 0.2},
        http_client_kwargs={"transport": httpx.MockTransport(respond)},
    )
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    try:
        assert wrapper.run(prompt="query", system_prompt="system", generation_kwargs={"temperature": 0.3}) == {
            "replies": ["answer"],
        }
        assert requests == [{"model": "gpt-test", "messages": [
            {"role": "system", "content": "system"}, {"role": "user", "content": "query"},
        ], "temperature": 0.3, "stream": False, "n": 1}]
    finally:
        wrapper.close()


def test_openai_generator_preserves_authentication_errors_and_streaming_callback():
    def deny(request):
        return httpx.Response(401, json={"error": {"message": "bad key", "type": "authentication_error"}})

    generator = generator_config.OpenAIChatGenerator(
        api_key=generator_config.Secret.from_token("test-key"), max_retries=0,
        http_client_kwargs={"transport": httpx.MockTransport(deny)},
    )
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    try:
        with pytest.raises(AuthenticationError, match="bad key"):
            wrapper.run(prompt="query")
    finally:
        wrapper.close()

    chunks = []

    def stream(request):
        events = [
            {"index": 0, "delta": {"role": "assistant", "content": "answer"}, "finish_reason": None},
            {"index": 0, "delta": {}, "finish_reason": "stop"},
        ]
        responses = [
            {"id": "test", "object": "chat.completion.chunk", "created": 0, "model": "gpt-test", "choices": [event]}
            for event in events
        ]
        data = "".join(f"data: {json.dumps(response)}\n\n" for response in responses)
        data += "data: [DONE]\n\n"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=data)

    generator = generator_config.OpenAIChatGenerator(
        api_key=generator_config.Secret.from_token("test-key"), max_retries=0,
        http_client_kwargs={"transport": httpx.MockTransport(stream)},
    )
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    try:
        assert wrapper.run(prompt="query", streaming_callback=chunks.append) == {"replies": ["answer"]}
        assert "".join(chunk.content for chunk in chunks) == "answer"
        assert chunks[-1].finish_reason == "stop"
    finally:
        wrapper.close()


def test_generator_factory_reports_missing_openai_credentials_during_initialization(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        GeneratorConfig(openai_model="gpt-test").create_generator()


@pytest.mark.parametrize("provider", [pytest.param("ollama", id="local-sdk"), "bedrock", "google", "litellm"])
def test_real_provider_adapters_preserve_requests_replies_and_errors(monkeypatch, provider):
    client = Mock()
    if provider == "ollama":
        from ollama import ChatResponse

        module = importlib.import_module(generator_config.OllamaChatGenerator.__module__)
        monkeypatch.setattr(module, "Client", Mock(return_value=client))
        monkeypatch.setattr(module, "AsyncClient", Mock())
        client.chat.return_value = ChatResponse(
            model="llama-test", message={"role": "assistant", "content": "answer"}, done=True,
            prompt_eval_count=2, eval_count=1,
        )
        call = client.chat
        config = GeneratorConfig(ollama_model="llama-test", ollama_host="localhost:11434")
    elif provider == "bedrock":
        module = importlib.import_module(generator_config.AmazonBedrockChatGenerator.__module__)
        session = Mock()
        session.client.return_value = client
        monkeypatch.setattr(module, "get_aws_session", Mock(return_value=session))
        client.converse.return_value = {
            "output": {"message": {"role": "assistant", "content": [{"text": "answer"}]}},
            "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        }
        call = client.converse
        config = GeneratorConfig(bedrock_model="bedrock-test")
    elif provider == "google":
        from google.genai import types

        module = importlib.import_module(generator_config.GoogleGenAIChatGenerator.__module__)
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        monkeypatch.setattr(module, "_get_client", Mock(return_value=Mock()))
        monkeypatch.setattr(generator_config, "Client", Mock(return_value=client))
        client.models.generate_content.return_value = types.GenerateContentResponse(
            candidates=[types.Candidate(content=types.Content(role="model", parts=[types.Part(text="answer")]),
                                        finish_reason="STOP")],
            model_version="gemini-test",
        )
        call = client.models.generate_content
        config = GeneratorConfig(gemini_model="gemini-test")
    else:
        call = Mock(return_value=SimpleNamespace(
            model="provider/model", choices=[SimpleNamespace(
                message=SimpleNamespace(content="answer", tool_calls=[]), index=0, finish_reason="stop",
            )],
        ))
        monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=call))
        config = GeneratorConfig(litellm_model="provider/model", litellm_api_key="test-key",
                                 litellm_api_base="https://proxy.example/v1")

    wrapper = config.create_generator(temperature=0.2)
    try:
        assert wrapper.run(prompt="query", system_prompt="system", generation_kwargs={"temperature": 0.3}) == {
            "replies": ["answer"],
        }
        request = call.call_args.kwargs
        if provider == "google":
            assert request["model"] == "gemini-test"
            assert request["config"].system_instruction == "system"
            assert request["config"].temperature == 0.3
            assert request["contents"][0].parts[0].text == "query"
        elif provider == "bedrock":
            assert request["modelId"] == "bedrock-test"
            assert request["inferenceConfig"]["temperature"] == 0.3
            assert request["system"] == [{"text": "system"}]
            assert request["messages"] == [{"role": "user", "content": [{"text": "query"}]}]
        else:
            assert request["messages"] == [
                {"role": "system", "content": "system"}, {"role": "user", "content": "query"},
            ]
            if provider == "ollama":
                assert request["model"] == "llama-test"
                assert request["options"]["temperature"] == 0.3
            else:
                assert request["model"] == "provider/model"
                assert request["temperature"] == 0.3
                assert request["api_key"] == "test-key"
                assert request["api_base"] == "https://proxy.example/v1"
        call.side_effect = RuntimeError("provider failed")
        with pytest.raises(RuntimeError, match="provider failed"):
            wrapper.run(prompt="query")
    finally:
        wrapper.close()


class FakeComponent:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def run(self, documents=None, **kwargs):
        return {"documents": documents or []}


def test_generator_config_from_env_args_defaults_check_and_describe(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "ollama:11434")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    monkeypatch.setenv("TEMPERATURE", "0.7")

    env_config = GeneratorConfig.from_env()
    args_config = GeneratorConfig.from_args(argparse.Namespace(
        ollama_host=None,
        ollama_model="llama",
        gemini_model=None,
        openai_model=None,
        bedrock_model=None,
        litellm_model="openai/gpt-test",
        litellm_api_base=None,
        temperature=0.3,
    ))

    assert env_config.ollama_host == "ollama:11434"
    assert env_config.openai_model == "gpt-test"
    assert env_config.temperature == 0.7
    assert args_config.ollama_model == "llama"
    assert args_config.openai_model == "gpt-test"
    assert args_config.litellm_model == "openai/gpt-test"
    assert env_config.check() is env_config
    assert env_config.describe() == "OpenAI gpt-test"
    assert GeneratorConfig(ollama_model="llama",
                           ollama_host="ollama:11434").describe() == "Ollama llama at ollama:11434"


def test_generator_config_supports_litellm(monkeypatch):
    monkeypatch.setenv("LITELLM_MODEL", "openai/gpt-4.1-mini")
    monkeypatch.setenv("LITELLM_API_BASE", "https://litellm.example/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "test-key")

    config = GeneratorConfig.from_env()

    assert config.litellm_model == "openai/gpt-4.1-mini"
    assert config.litellm_api_base == "https://litellm.example/v1"
    assert config.litellm_api_key == "test-key"
    assert config.check() is config
    assert config.describe() == "LiteLLM openai/gpt-4.1-mini"


def test_apply_summarizing_default_picks_available_provider(monkeypatch):
    for key in ["GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"]:
        monkeypatch.delenv(key, raising=False)
    assert GeneratorConfig().apply_summarizing_default().ollama_model == "llama3.2:3b"

    monkeypatch.setenv("OPENAI_API_KEY", "key")
    config = GeneratorConfig().apply_summarizing_default()
    assert config.openai_model == "gpt-5-nano"
    assert config.ollama_host == generator_config.OLLAMA_HOST_DEFAULT

    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setenv("GEMINI_API_KEY", "key")
    assert GeneratorConfig().apply_summarizing_default().gemini_model == "gemini-flash-lite-latest"

    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "key")
    assert GeneratorConfig().apply_summarizing_default().bedrock_model == "us.meta.llama3-2-3b-instruct-v1:0"


def test_generator_config_rejects_missing_provider_and_describes_providers():
    with pytest.raises(AssertionError):
        GeneratorConfig().check()

    assert GeneratorConfig(gemini_model="gemini").describe() == "Gemini gemini"
    assert GeneratorConfig(bedrock_model="bedrock").describe() == "Bedrock bedrock"
    assert GeneratorConfig(litellm_model="provider/model").describe() == "LiteLLM provider/model"


def test_embedder_enable_handles_request_failures(monkeypatch):
    config = GeneratorConfig(ollama_host="host:11434", ollama_model="model:latest")
    monkeypatch.setattr(generator_config.requests, "get", lambda *args, **kwargs: (_ for _ in ()).throw(OSError()))
    assert config._embedder_enable_ollama() is False


def test_ollama_url_pull_and_embedder_enable(monkeypatch):
    config = GeneratorConfig(ollama_host="host:11434")

    class Response:
        def __init__(self, payload=None):
            self.payload = payload or {}

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    monkeypatch.setattr(generator_config.requests, "get", lambda url: Response({"version": "0.14.1"}))

    assert config.ollama_url() == "http://host:11434"
    assert config._embedder_enable_ollama() is True


def test_embedder_model_name_to_path_for_providers(monkeypatch):
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: True)

    assert GeneratorConfig(gemini_model="gemini")._embedder_model_name_to_path(
        "nomic-embed-text") == "text-embedding-004"
    assert GeneratorConfig(gemini_model="gemini")._embedder_model_name_to_path(
        "jina-embeddings-v2-base-code") == "gemini-embedding-001"
    assert GeneratorConfig(bedrock_model="bedrock")._embedder_model_name_to_path(
        "anything") == "amazon.titan-embed-text-v2:0"
    assert GeneratorConfig(ollama_model="llama")._embedder_model_name_to_path(
        "nomic-embed-text") == "nomic-embed-text:latest"
    assert GeneratorConfig()._embedder_model_name_to_path(
        "all-MiniLM-L6-v2") == "sentence-transformers/all-MiniLM-L6-v2"
    assert GeneratorConfig()._embedder_model_name_to_path("unknown") == "unknown"


def test_create_generator_selects_provider(monkeypatch):
    monkeypatch.setattr(generator_config, "OpenAIChatGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "LiteLLMChatGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "GoogleGenAIGeneratorWithRetry", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockChatGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaChatGenerator", FakeComponent)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: None)

    assert GeneratorConfig(openai_model="gpt-5-test").create_generator().chat_generator.kwargs["generation_kwargs"][
               "temperature"] == 1.0
    assert GeneratorConfig(litellm_model="openai/gpt-4.1-mini").create_generator().chat_generator.kwargs[
               "model"] == "openai/gpt-4.1-mini"
    assert GeneratorConfig(litellm_model="openai/gpt-4.1-mini",
                           litellm_api_base="https://litellm.example/v1").create_generator().chat_generator.kwargs[
               "api_base_url"] == "https://litellm.example/v1"
    assert GeneratorConfig(gemini_model="gemini").create_generator().kwargs["model"] == "gemini"
    assert GeneratorConfig(bedrock_model="bedrock").create_generator().chat_generator.kwargs["model"] == "bedrock"
    assert GeneratorConfig(ollama_model="llama", ollama_host="host").create_generator().chat_generator.kwargs[
               "model"] == "llama"
    assert GeneratorConfig(openai_model="gpt-4").create_generator().chat_generator.kwargs[
               "generation_kwargs"]["temperature"] == generator_config.TEMPERATURE_DEFAULT

    with pytest.raises(NotImplementedError):
        GeneratorConfig().create_generator()


def test_create_embedders_and_sparse_embedders(monkeypatch):
    monkeypatch.setattr(generator_config, "GoogleGenAIDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "GoogleGenAITextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "SentenceTransformersDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "SentenceTransformersTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "FastembedSparseDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "FastembedSparseTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "process_cpu_count", lambda: 8)
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: True)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: None)
    model = ModelConfig("nomic-embed-text", 256)

    assert GeneratorConfig(gemini_model="gemini").create_document_embedder(model).kwargs[
               "model"] == "text-embedding-004"
    assert GeneratorConfig(gemini_model="gemini").create_text_embedder(model).kwargs["model"] == "text-embedding-004"
    assert GeneratorConfig(bedrock_model="bedrock").create_document_embedder(model).kwargs[
               "model"] == "amazon.titan-embed-text-v2:0"
    assert GeneratorConfig(bedrock_model="bedrock").create_text_embedder(model).kwargs[
               "model"] == "amazon.titan-embed-text-v2:0"
    assert GeneratorConfig(ollama_model="llama").create_document_embedder(model).kwargs[
               "model"] == "nomic-embed-text:latest"
    assert GeneratorConfig(ollama_model="llama").create_text_embedder(model).kwargs[
               "model"] == "nomic-embed-text:latest"
    assert GeneratorConfig().create_document_embedder(model).kwargs["model"] == "nomic-ai/nomic-embed-text-v1.5"
    assert GeneratorConfig().create_text_embedder(model).kwargs["model"] == "nomic-ai/nomic-embed-text-v1.5"
    assert GeneratorConfig().create_sparse_document_embedder(model).kwargs["threads"] == 4
    assert GeneratorConfig().create_sparse_text_embedder(model).kwargs["threads"] == 4


def test_sparse_embedder_cache_dir_can_be_disabled(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    assert GeneratorConfig()._fastembed_cache_dir() is None


def test_safe_embedder_returns_embedded_docs_or_original_on_error():
    docs = [Document(content="doc")]

    class Working:
        def run(self, documents):
            return {"documents": [Document(content="embedded")]}

    class Broken:
        def run(self, documents):
            raise RuntimeError("failed")

    assert safe_embedder(Working(), docs)[0].content == "embedded"
    assert safe_embedder(Broken(), docs) is docs


def test_chat_generator_compatibility_wrapper_converts_chat_replies():
    class ChatGenerator:
        def run(self, **kwargs):
            return {"replies": [ChatMessage.from_assistant("one"), ChatMessage.from_assistant("two")]}

    wrapper = ChatGeneratorCompatibilityWrapper(ChatGenerator())
    result = wrapper.run(prompt="user", system_prompt="system")

    assert result == {"replies": ["one", "two"]}


def test_chat_generator_compatibility_wrapper_handles_empty_replies():
    class ChatGenerator:
        def run(self, **kwargs):
            return {"replies": []}

    wrapper = ChatGeneratorCompatibilityWrapper(ChatGenerator())
    result = wrapper.run(prompt="user")

    assert result == {"replies": []}
