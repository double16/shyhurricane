import argparse

import pytest
from haystack.dataclasses import ChatMessage

import shyhurricane.generator_config as generator_config
from shyhurricane.doc_type_model_map import ModelConfig
from shyhurricane.generator_config import (
    GeneratorConfig,
    GoogleGenAIGeneratorWithRetry,
    add_generator_args,
)


pytestmark = pytest.mark.ollama


class FakeComponent:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_generator_args_and_env_provider_selection(monkeypatch):
    parser = argparse.ArgumentParser()
    add_generator_args(parser)
    args = parser.parse_args([
        "--ollama-host", "127.0.0.1:11434",
        "--ollama-model", "llama3.2:3b",
        "--gemini-model", "gemini-test",
        "--openai-model", "gpt-test",
        "--bedrock-model", "bedrock-test",
        "--temperature", "0.4",
    ])

    config = GeneratorConfig.from_args(args)

    assert config.ollama_host == "127.0.0.1:11434"
    assert config.ollama_model == "llama3.2:3b"
    assert config.gemini_model == "gemini-test"
    assert config.openai_model == "gpt-test"
    assert config.bedrock_model == "bedrock-test"
    assert config.temperature == 0.4

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")

    defaulted = GeneratorConfig().apply_summarizing_default()

    assert defaulted.bedrock_model == "us.meta.llama3-2-3b-instruct-v1:0"
    assert defaulted.ollama_host == generator_config.OLLAMA_HOST_DEFAULT
    assert defaulted.describe() == "Bedrock us.meta.llama3-2-3b-instruct-v1:0"


def test_ollama_version_check_accepts_new_versions_and_rejects_errors(monkeypatch):
    class Response:
        def __init__(self, version="0.14.0", exc=None):
            self.version = version
            self.exc = exc

        def raise_for_status(self):
            if self.exc:
                raise self.exc

        def json(self):
            return {"version": self.version}

    config = GeneratorConfig(ollama_host="ollama:11434")

    monkeypatch.setattr(generator_config.requests, "get", lambda url: Response("0.14.1"))
    assert config._embedder_enable_ollama() is True

    monkeypatch.setattr(generator_config.requests, "get", lambda url: Response("0.13.9"))
    assert config._embedder_enable_ollama() is False

    monkeypatch.setattr(generator_config.requests, "get", lambda url: Response(exc=RuntimeError("down")))
    assert config._embedder_enable_ollama() is False


def test_ollama_generator_and_embedders_use_ollama_components(monkeypatch):
    pulls = []
    monkeypatch.setattr(generator_config, "OllamaGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaTextEmbedder", FakeComponent)
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: True)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: pulls.append(model))

    config = GeneratorConfig(ollama_model="llama3.2:3b", ollama_host="ollama:11434", temperature=0.2)
    model = ModelConfig("all-MiniLM-L6-v2", 256)

    generator = config.create_generator(temperature=0.5, generation_kwargs={"num_ctx": 4096})
    doc_embedder = config.create_document_embedder(model)
    text_embedder = config.create_text_embedder(model)

    assert generator.kwargs == {
        "url": "http://ollama:11434",
        "model": "llama3.2:3b",
        "generation_kwargs": {"temperature": 0.5, "num_ctx": 4096},
    }
    assert doc_embedder.kwargs == {
        "model": "mahonzhan/all-MiniLM-L6-v2:latest",
        "url": "http://ollama:11434",
        "progress_bar": False,
    }
    assert text_embedder.kwargs == {
        "model": "mahonzhan/all-MiniLM-L6-v2:latest",
        "url": "http://ollama:11434",
    }
    assert pulls == [
        "llama3.2:3b",
        "mahonzhan/all-MiniLM-L6-v2:latest",
        "mahonzhan/all-MiniLM-L6-v2:latest",
    ]


def test_embedder_model_mapping_and_local_fallbacks(monkeypatch):
    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: False)
    monkeypatch.setattr(generator_config, "SentenceTransformersDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "SentenceTransformersTextEmbedder", FakeComponent)

    ollama_config = GeneratorConfig(ollama_model="llama3.2:3b")
    local_config = GeneratorConfig()

    assert ollama_config._embedder_model_name_to_path("nomic-embed-code") == "jinaai/jina-embeddings-v2-base-code"
    assert ollama_config._embedder_model_name_to_path("custom-model") == "custom-model"

    doc_embedder = local_config.create_document_embedder(ModelConfig("nomic-embed-code", 256))
    text_embedder = local_config.create_text_embedder(ModelConfig("custom-model", 256))

    assert doc_embedder.kwargs["model"] == "jinaai/jina-embeddings-v2-base-code"
    assert doc_embedder.kwargs["batch_size"] == 1
    assert doc_embedder.kwargs["model_kwargs"] == {"attn_implementation": "eager"}
    assert text_embedder.kwargs["model"] == "custom-model"
    assert text_embedder.kwargs["normalize_embeddings"] is True


def test_provider_embedder_construction_and_sparse_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(generator_config, "GoogleGenAIDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "GoogleGenAITextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "FastembedSparseDocumentEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "FastembedSparseTextEmbedder", FakeComponent)
    monkeypatch.setattr(generator_config, "process_cpu_count", lambda: 6)
    monkeypatch.setenv("HOME", str(tmp_path))

    model = ModelConfig("unknown-embedder", 256)
    sparse = ModelConfig("sparse-model", 256)

    assert GeneratorConfig(gemini_model="gemini").create_document_embedder(model).kwargs["model"] == "text-embedding-004"
    assert GeneratorConfig(gemini_model="gemini").create_text_embedder(model).kwargs["model"] == "text-embedding-004"
    assert GeneratorConfig(bedrock_model="bedrock").create_document_embedder(model).kwargs[
        "model"] == "amazon.titan-embed-text-v2:0"
    assert GeneratorConfig(bedrock_model="bedrock").create_text_embedder(model).kwargs[
        "model"] == "amazon.titan-embed-text-v2:0"

    doc_sparse = GeneratorConfig().create_sparse_document_embedder(sparse)
    text_sparse = GeneratorConfig().create_sparse_text_embedder(sparse)

    assert doc_sparse.kwargs["cache_dir"] == str(tmp_path / ".cache/fastembed")
    assert doc_sparse.kwargs["threads"] == 3
    assert doc_sparse.kwargs["batch_size"] == 32
    assert text_sparse.kwargs["cache_dir"] == str(tmp_path / ".cache/fastembed")
    assert text_sparse.kwargs["parallel"] == 0


def test_google_generator_wrapper_converts_chat_replies(monkeypatch):
    class ChatGenerator:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.calls = []

        def run(self, **kwargs):
            self.calls.append(kwargs)
            return {"replies": [ChatMessage.from_assistant("one"), ChatMessage.from_assistant("two")]}

    monkeypatch.setattr(generator_config, "GoogleGenAIChatGeneratorWithRetry", ChatGenerator)

    wrapper = GoogleGenAIGeneratorWithRetry(model="gemini-test", generation_kwargs={"temperature": 0.2})
    result = wrapper.run(
        prompt="user",
        system_prompt="system",
        generation_kwargs={"temperature": 0.3},
        safety_settings=[{"category": "test"}],
        streaming_callback="callback",
    )

    call = wrapper.chat_generator.calls[0]
    assert result == {"replies": ["one", "two"]}
    assert [message.texts[0] for message in call["messages"]] == ["system", "user"]
    assert call["generation_kwargs"] == {"temperature": 0.3}
    assert call["safety_settings"] == [{"category": "test"}]
    assert call["streaming_callback"] == "callback"
