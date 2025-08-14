import argparse
import logging
import os
from typing import Optional, Dict, Any, Union, List

from google.genai import Client
from google.genai.types import HttpOptions, HttpRetryOptions
from haystack.components.generators import OpenAIGenerator
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.tools import Toolset
from haystack.utils import Secret
from haystack import component
from haystack.dataclasses import ChatMessage, StreamingCallbackT
from haystack_integrations.components.generators.google_genai.chat.chat_generator import GoogleGenAIChatGenerator
from haystack_integrations.components.generators.ollama import OllamaChatGenerator, OllamaGenerator
from mcp import Tool
from pydantic import BaseModel, Field

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
    ap.add_argument("--temperature", help="The temperature of the generators", default=TEMPERATURE_DEFAULT, type=float)


TEMPERATURE_DEFAULT: float = 0.2


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
    temperature: float = Field(description="The temperature of the generator", default=TEMPERATURE_DEFAULT)

    @staticmethod
    def from_args(args):
        generator_config = GeneratorConfig(
            ollama_host=args.ollama_host or os.environ.get("OLLAMA_HOST", None),
            ollama_model=args.ollama_model or os.environ.get("OLLAMA_MODEL", None),
            gemini_model=args.gemini_model or os.environ.get("GEMINI_MODEL", None),
            openai_model=args.openai_model or os.environ.get("OPENAI_MODEL", None),
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
            temperature=float(os.environ.get("TEMPERATURE", str(TEMPERATURE_DEFAULT))),
        )
        return generator_config

    def apply_reasoning_default(self):
        if self.ollama_model or self.gemini_model or self.openai_model:
            return self
        if os.environ.get("GEMINI_API_KEY", None) or os.environ.get("GOOGLE_API_KEY", None):
            self.gemini_model = "gemini-2.5-flash"
        elif os.environ.get("OPENAI_API_KEY", None):
            self.openai_model = "o4-mini"
        else:
            self.ollama_model = "qwen3:8b"
        return self

    def apply_summarizing_default(self):
        if self.ollama_model or self.gemini_model or self.openai_model:
            return self
        if os.environ.get("GEMINI_API_KEY", None) or os.environ.get("GOOGLE_API_KEY", None):
            self.gemini_model = "gemini-2.0-flash-lite"
        elif os.environ.get("OPENAI_API_KEY", None):
            self.openai_model = "gpt-4-turbo"
        else:
            self.ollama_model = "llama3.2:3b"
        return self

    def check(self):
        assert self.ollama_model or self.gemini_model or self.openai_model
        return self

    def describe(self) -> str:
        if self.openai_model:
            return f"OpenAI {self.openai_model}"
        elif self.gemini_model:
            return f"Gemini {self.gemini_model}"
        else:
            if self.ollama_host:
                return f"Ollama {self.ollama_model} at {self.ollama_host}"
            else:
                return f"Ollama {self.ollama_model}"

    def create_chat_generator(self,
                              temperature: Optional[float] = None,
                              generation_kwargs: Optional[Dict[str, Any]] = None,
                              tools: Optional[Union[List[Tool], Toolset]] = None):
        if self.openai_model:
            logger.info("Using OpenAI chat with model %s", self.openai_model)
            if self.openai_model.startswith("o4-mini"):
                temperature = 1.0
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return OpenAIChatGenerator(
                model=self.openai_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                max_retries=10,
                tools=tools
            )
        elif self.gemini_model:
            logger.info("Using Google Gemini chat with model %s", self.gemini_model)
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return GoogleGenAIChatGeneratorWithRetry(
                model=self.gemini_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                tools=tools
            )
        elif self.ollama_model:
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            if self.ollama_host:
                logger.info("Using Ollama chat with model %s at %s", self.ollama_model, self.ollama_host)
                return OllamaChatGenerator(
                    url="http://" + self.ollama_host,
                    model=self.ollama_model,
                    generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                    tools=tools,
                    think=True,
                )
            else:
                logger.info("Using Ollama chat with model %s", self.ollama_model)
                return OllamaChatGenerator(
                    model=self.ollama_model,
                    generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                    tools=tools,
                    think=True,
                )
        else:
            raise NotImplementedError

    def create_generator(self,
                         temperature: Optional[float] = None,
                         generation_kwargs: Optional[Dict[str, Any]] = None):
        if self.openai_model:
            logger.info("Using OpenAI generator with model %s", self.openai_model)
            if self.openai_model.startswith("o4-mini"):
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
            logger.info("Using Google Gemini chat with model %s", self.gemini_model)
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            return GoogleGenAIGeneratorWithRetry(
                model=self.gemini_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
            )
        elif self.ollama_model:
            _generation_kwargs = {
                "temperature": temperature or self.temperature,
            }
            if self.ollama_host:
                logger.info("Using Ollama generator with model %s at %s", self.ollama_model, self.ollama_host)
                return OllamaGenerator(
                    url="http://" + self.ollama_host,
                    model=self.ollama_model,
                    generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                )
            else:
                logger.info("Using Ollama generator with model %s", self.ollama_model)
                return OllamaGenerator(
                    model=self.ollama_model,
                    generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                )
        else:
            raise NotImplementedError
