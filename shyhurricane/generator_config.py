import argparse
import logging
import os
from math import ceil
from typing import Optional, Dict, Any, List

import requests
from google.genai import Client
from google.genai.types import HttpOptions, HttpRetryOptions
from haystack.components.embedders import SentenceTransformersDocumentEmbedder, SentenceTransformersTextEmbedder
from haystack.components.generators import OpenAIGenerator
from haystack.core.component import Component
from haystack.utils import Secret
from haystack import component, Document
from haystack.dataclasses import ChatMessage, StreamingCallbackT
from haystack_integrations.components.embedders.amazon_bedrock import AmazonBedrockDocumentEmbedder, \
    AmazonBedrockTextEmbedder
from haystack_integrations.components.embedders.fastembed import FastembedSparseDocumentEmbedder, \
    FastembedSparseTextEmbedder
from haystack_integrations.components.embedders.google_genai import GoogleGenAIDocumentEmbedder, GoogleGenAITextEmbedder
from haystack_integrations.components.embedders.ollama import OllamaDocumentEmbedder, OllamaTextEmbedder
from haystack_integrations.components.generators.amazon_bedrock import AmazonBedrockGenerator
from haystack_integrations.components.generators.google_genai.chat.chat_generator import GoogleGenAIChatGenerator
from haystack_integrations.components.generators.ollama import OllamaGenerator
from pydantic import BaseModel, Field

from shyhurricane.doc_type_model_map import ModelConfig
from shyhurricane.utils import process_cpu_count

logger = logging.getLogger(__name__)


def add_generator_args(ap: argparse.ArgumentParser):
    ap.add_argument("--ollama-host", help="The location (host:port) for the Ollama service", required=False)
    ap.add_argument("--ollama-model",
                    help="Use Ollama with the specified model (qwen instruct models are recommended), must already be pulled",
                    required=False)
    ap.add_argument("--gemini-model",
                    help="Use Google Gemini with the specified model (gemini-2.5-pro is recommended), API key must be in env var GOOGLE_API_KEY or GEMINI_API_KEY",
                    required=False)
    ap.add_argument("--openai-model",
                    help="Use OpenAI with the specified model (o4-mini is recommended), API key must be in env var OPENAI_API_KEY",
                    required=False)
    ap.add_argument("--bedrock-model",
                    help="Use AWS Bedrock with the specified model (anthropic.claude-sonnet-4-5-20250929-v1:0 is recommended), AWS credentials must be provided in the same way as the aws cli",
                    required=False)
    ap.add_argument("--temperature", help="The temperature of the generators", default=TEMPERATURE_DEFAULT, type=float)


TEMPERATURE_DEFAULT: float = 0.2
OLLAMA_HOST_DEFAULT = "localhost:11434"


class GoogleGenAIChatGeneratorWithRetry(GoogleGenAIChatGenerator):
    def __init__(self,
                 api_key: Secret = Secret.from_env_var(["GOOGLE_API_KEY", "GEMINI_API_KEY"], strict=True),
                 **kwargs):
        super().__init__(**kwargs)
        self._client = Client(
            api_key=api_key.resolve_value(),
            http_options=HttpOptions(
                retry_options=HttpRetryOptions(
                    attempts=10,
                    exp_base=4.0,
                )
            )
        )


@component
class GoogleGenAIGeneratorWithRetry:
    def __init__(self, *args, **kwargs):
        self.chat_generator = GoogleGenAIChatGeneratorWithRetry(*args, **kwargs)

    @component.output_types(replies=List[str])
    def run(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            generation_kwargs: Optional[Dict[str, Any]] = None,
            safety_settings: Optional[List[Dict[str, Any]]] = None,
            streaming_callback: Optional[StreamingCallbackT] = None,
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append(ChatMessage.from_system(system_prompt))
        messages.append(ChatMessage.from_user(prompt))
        chat_result = self.chat_generator.run(
            messages=messages,
            generation_kwargs=generation_kwargs,
            safety_settings=safety_settings,
            streaming_callback=streaming_callback,
        )
        text_result = []
        for reply in chat_result.get("replies", []):
            text_result.extend(reply.texts)
        return {"replies": text_result}


class GeneratorConfig(BaseModel):
    ollama_host: Optional[str] = Field(description="The location of the Ollama server", default=None)
    ollama_model: Optional[str] = Field(description="The name of the Ollama model", default=None)
    gemini_model: Optional[str] = Field(description="The name of the Gemini model", default=None)
    openai_model: Optional[str] = Field(description="The name of the OpenAI model", default=None)
    bedrock_model: Optional[str] = Field(description="The name of the AWS Bedrock model", default=None)
    temperature: float = Field(description="The temperature of the generator", default=TEMPERATURE_DEFAULT)

    @staticmethod
    def from_args(args):
        generator_config = GeneratorConfig(
            ollama_host=args.ollama_host or os.environ.get("OLLAMA_HOST", None),
            ollama_model=args.ollama_model or os.environ.get("OLLAMA_MODEL", None),
            gemini_model=args.gemini_model or os.environ.get("GEMINI_MODEL", None),
            openai_model=args.openai_model or os.environ.get("OPENAI_MODEL", None),
            bedrock_model=args.bedrock_model or os.environ.get("BEDROCK_MODEL", None),
            temperature=args.temperature,
        )
        return generator_config

    @staticmethod
    def from_env():
        generator_config = GeneratorConfig(
            ollama_host=os.environ.get("OLLAMA_HOST", None),
            ollama_model=os.environ.get("OLLAMA_MODEL", None),
            gemini_model=os.environ.get("GEMINI_MODEL", None),
            openai_model=os.environ.get("OPENAI_MODEL", None),
            bedrock_model=os.environ.get("BEDROCK_MODEL", None),
            temperature=float(os.environ.get("TEMPERATURE", str(TEMPERATURE_DEFAULT))),
        )
        return generator_config

    def ollama_url(self) -> str:
        return "http://" + (self.ollama_host or OLLAMA_HOST_DEFAULT)

    def ollama_pull(self, model_id: str):
        model, tag = model_id.rsplit(":", maxsplit=1)
        r = requests.post(f"{self.ollama_url()}/api/pull", json={"model": model, "tag": tag, "force": False})
        r.raise_for_status()

    def apply_summarizing_default(self):
        self.ollama_host = self.ollama_host or OLLAMA_HOST_DEFAULT
        if self.ollama_model or self.gemini_model or self.openai_model or self.bedrock_model:
            return self
        if os.environ.get("GEMINI_API_KEY", None) or os.environ.get("GOOGLE_API_KEY", None):
            self.gemini_model = "gemini-flash-lite-latest"
        elif os.environ.get("OPENAI_API_KEY", None):
            self.openai_model = "gpt-5-nano"
        elif os.environ.get("AWS_SECRET_ACCESS_KEY", None):
            self.bedrock_model = "us.meta.llama3-2-3b-instruct-v1:0"
        else:
            self.ollama_model = "llama3.2:3b"
        return self

    def check(self):
        assert self.ollama_model or self.gemini_model or self.openai_model or self.bedrock_model
        return self

    def describe(self) -> str:
        if self.openai_model:
            return f"OpenAI {self.openai_model}"
        elif self.gemini_model:
            return f"Gemini {self.gemini_model}"
        elif self.bedrock_model:
            return f"Bedrock {self.bedrock_model}"
        else:
            return f"Ollama {self.ollama_model} at {self.ollama_host}"

    def create_generator(self,
                         temperature: Optional[float] = None,
                         generation_kwargs: Optional[Dict[str, Any]] = None):
        if self.openai_model:
            logger.info("Using OpenAI generator with model %s", self.openai_model)
            if self.openai_model.startswith("o4-mini") or self.openai_model.startswith("gpt-5"):
                temperature = 1.0
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return OpenAIGenerator(
                model=self.openai_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                max_retries=10,
            )
        elif self.gemini_model:
            logger.info("Using Google Gemini generator with model %s", self.gemini_model)
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return GoogleGenAIGeneratorWithRetry(
                model=self.gemini_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
            )
        elif self.bedrock_model:
            logger.info("Using AWS Bedrock generator with model %s", self.bedrock_model)
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return AmazonBedrockGenerator(
                model=self.bedrock_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
            )
        elif self.ollama_model:
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            logger.info("Using Ollama generator with model %s at %s", self.ollama_model, self.ollama_host)
            self.ollama_pull(self.ollama_model)
            return OllamaGenerator(
                url=self.ollama_url(),
                model=self.ollama_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
            )
        else:
            raise NotImplementedError

    def _embedder_enable_ollama(self) -> bool:
        # v0.12.11, v0.13.0 - macos has use after free failures
        # v0.14.0 - macos embedding is working
        try:
            resp_version = requests.get(self.ollama_url() + "/api/version")
            resp_version.raise_for_status()
            version = float(".".join(resp_version.json()["version"].split(".")[0:2]))
            return version >= 0.14
        except Exception:
            return False

    def _embedder_model_name_to_path(self, model_name: str) -> str:
        """
        This is a hack. We should have a fixed set of model_purpose like Literal["text","code"], then map to models. This
        method should return the max token length since it is model dependent.
        :param model_name:
        :return:
        """
        if self.openai_model:
            pass
        elif self.gemini_model:
            match model_name:
                case "nomic-embed-text" | "all-MiniLM-L6-v2":
                    return "text-embedding-004"
                case "nomic-embed-code" | "jina-embeddings-v2-base-code":
                    return "gemini-embedding-001"
                case _:
                    return "text-embedding-004"
        elif self.bedrock_model:
            return "amazon.titan-embed-text-v2:0"
        elif self.ollama_model and self._embedder_enable_ollama():
            match model_name:
                case "all-MiniLM-L6-v2":
                    return "mahonzhan/all-MiniLM-L6-v2:latest"
                case "nomic-embed-text":
                    return "nomic-embed-text:latest"
                case "jina-embeddings-v2-base-code":
                    return "unclemusclez/jina-embeddings-v2-base-code:latest"
                case "nomic-embed-code":
                    return "manutic/nomic-embed-code:latest"
                case _:
                    return model_name

        match model_name:
            case "all-MiniLM-L6-v2":
                return "sentence-transformers/all-MiniLM-L6-v2"
            case "nomic-embed-text":
                return "nomic-ai/nomic-embed-text-v1.5"
            case "nomic-embed-code" | "jina-embeddings-v2-base-code":
                return "jinaai/jina-embeddings-v2-base-code"
            # case "nomic-embed-code":  # too large
            #     return "manutic/nomic-embed-code:latest"
            case _:
                return model_name

    def create_document_embedder(self, model_config: ModelConfig):
        model_path = self._embedder_model_name_to_path(model_config.model_name)
        if self.openai_model:
            logger.info("Using OpenAI document embedder with model %s", model_path)
        elif self.gemini_model:
            logger.info("Using Google Gemini document embedder with model %s", model_path)
            return GoogleGenAIDocumentEmbedder(
                model=model_path,
                progress_bar=False,
            )
        elif self.bedrock_model:
            logger.info("Using AWS Bedrock document embedder with model %s", model_path)
            return AmazonBedrockDocumentEmbedder(
                model="amazon.titan-embed-text-v2:0",
                progress_bar=False,
            )
        elif self.ollama_model and self._embedder_enable_ollama():
            logger.info("Using Ollama document embedder with model %s at %s", model_path, self.ollama_host)
            self.ollama_pull(model_path)
            return OllamaDocumentEmbedder(
                model=model_path,
                url=self.ollama_url(),
                progress_bar=False,
            )

        logger.info("Using local document embedder with model %s", model_path)
        embedder = SentenceTransformersDocumentEmbedder(
            model=model_path,
            batch_size=1,
            normalize_embeddings=True,
            trust_remote_code=True,
            progress_bar=False,
            model_kwargs={
                "attn_implementation": "eager",
            },
        )
        return embedder

    def create_text_embedder(self, model_config: ModelConfig):
        model_path = self._embedder_model_name_to_path(model_config.model_name)
        if self.openai_model:
            logger.info("Using OpenAI text embedder with model %s", model_path)
        elif self.gemini_model:
            logger.info("Using Google Gemini text embedder with model %s", model_path)
            return GoogleGenAITextEmbedder(
                model=model_path,
            )
        elif self.bedrock_model:
            logger.info("Using AWS Bedrock text embedder with model %s", model_path)
            return AmazonBedrockTextEmbedder(
                model="amazon.titan-embed-text-v2:0",
            )
        elif self.ollama_model and self._embedder_enable_ollama():
            logger.info("Using Ollama text embedder with model %s at %s", model_path, self.ollama_host)
            self.ollama_pull(model_path)
            return OllamaTextEmbedder(
                model=model_path,
                url=self.ollama_url(),
            )

        logger.info("Using local text embedder with model %s", model_path)
        embedder = SentenceTransformersTextEmbedder(
            model=model_path,
            batch_size=1,
            normalize_embeddings=True,
            trust_remote_code=True,
            progress_bar=False,
            model_kwargs={
                "attn_implementation": "eager",
            },
        )
        return embedder

    def _fastembed_cache_dir(self) -> Optional[str]:
        if "HOME" in os.environ:
            return os.path.join(os.environ["HOME"], ".cache/fastembed")
        return None

    def create_sparse_document_embedder(self, model_config: ModelConfig):
        return FastembedSparseDocumentEmbedder(
            model=model_config.model_name,
            cache_dir=self._fastembed_cache_dir(),
            threads=max(1, ceil(process_cpu_count() / 2)),
            batch_size=32,
            parallel=0,
            progress_bar=False,
        )

    def create_sparse_text_embedder(self, model_config: ModelConfig):
        return FastembedSparseTextEmbedder(
            model=model_config.model_name,
            cache_dir=self._fastembed_cache_dir(),
            threads=max(1, ceil(process_cpu_count() / 2)),
            parallel=0,
            progress_bar=False,
        )


def safe_embedder(embedder: Component, docs: List[Document]) -> List[Document]:
    """
    Attempts to run the embedding on the documents. If it fails, returns the docs without embeddings. Only use this if
    embeddings are optional.
    """
    try:
        return embedder.run(documents=docs)["documents"]
    except Exception as e:
        logger.error("Embedding documents, continuing without embeddings", e)
        return docs
