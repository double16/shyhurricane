import argparse

import pytest
from haystack import Document

import shyhurricane.generator_config as generator_config
from shyhurricane.doc_type_model_map import ModelConfig
from shyhurricane.generator_config import GeneratorConfig, safe_embedder


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
        temperature=0.3,
    ))

    assert env_config.ollama_host == "ollama:11434"
    assert env_config.openai_model == "gpt-test"
    assert env_config.temperature == 0.7
    assert args_config.ollama_model == "llama"
    assert args_config.openai_model == "gpt-test"
    assert env_config.check() is env_config
    assert env_config.describe() == "OpenAI gpt-test"
    assert GeneratorConfig(ollama_model="llama",
                           ollama_host="ollama:11434").describe() == "Ollama llama at ollama:11434"


def test_apply_summarizing_default_picks_available_provider(monkeypatch):
    for key in ["GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"]:
        monkeypatch.delenv(key, raising=False)
    assert GeneratorConfig().apply_summarizing_default().ollama_model == "llama3.2:3b"

    monkeypatch.setenv("OPENAI_API_KEY", "key")
    config = GeneratorConfig().apply_summarizing_default()
    assert config.openai_model == "gpt-5-nano"
    assert config.ollama_host == generator_config.OLLAMA_HOST_DEFAULT


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
    monkeypatch.setattr(generator_config, "OpenAIGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "GoogleGenAIGeneratorWithRetry", FakeComponent)
    monkeypatch.setattr(generator_config, "AmazonBedrockGenerator", FakeComponent)
    monkeypatch.setattr(generator_config, "OllamaGenerator", FakeComponent)
    monkeypatch.setattr(GeneratorConfig, "ollama_pull", lambda self, model: None)

    assert GeneratorConfig(openai_model="gpt-5-test").create_generator().kwargs["generation_kwargs"][
               "temperature"] == 1.0
    assert GeneratorConfig(gemini_model="gemini").create_generator().kwargs["model"] == "gemini"
    assert GeneratorConfig(bedrock_model="bedrock").create_generator().kwargs["model"] == "bedrock"
    assert GeneratorConfig(ollama_model="llama", ollama_host="host").create_generator().kwargs["model"] == "llama"

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
