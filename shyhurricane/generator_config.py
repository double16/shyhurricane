import argparse
import logging
import os
from typing import Optional, Dict, Any, Union, List

import requests
from google.genai import Client
from google.genai.types import HttpOptions, HttpRetryOptions
from haystack.components.generators import OpenAIGenerator
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.tools import Toolset
from haystack.utils import Secret
from haystack import component
from haystack.dataclasses import ChatMessage, StreamingCallbackT, ToolCall
from haystack_integrations.components.generators.google_genai.chat.chat_generator import GoogleGenAIChatGenerator
from haystack_integrations.components.generators.ollama import OllamaChatGenerator, OllamaGenerator
import haystack_integrations.components.generators.ollama.chat.chat_generator as ollama_cg
from mcp import Tool
from ollama import ChatResponse
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


# Monkey patch fix for OllamaChatGenerator, ollama-haystack==5.1.0
def _safe_convert_ollama_meta_to_openai_format(input_response_dict: Dict) -> Dict[str, Any]:
    """
    Map Ollama metadata keys onto the OpenAI-compatible names Haystack expects.
    All fields that are not part of the OpenAI metadata are left unchanged in the returned dict.

    Example Ollama metadata:
    {
        'model': 'phi4:14b-q4_K_M',
        'created_at': '2025-03-09T18:38:33.004185821Z',
        'done': True,
        'done_reason': 'stop',
        'total_duration': 86627206961,
        'load_duration': 23585622554,
        'prompt_eval_count': 26,
        'prompt_eval_duration': 3426000000,
        'eval_count': 298,
        'eval_duration': 4799921000
    }
    Example OpenAI metadata:
    {
        'model': 'phi4:14b-q4_K_M',
        'finish_reason': 'stop',
        'usage': {
            'completion_tokens': 298,
            'prompt_tokens': 26,
            'total_tokens': 324,
        }
        'completion_start_time': '2025-03-09T18:38:33.004185821Z',
        'done': True,
        'total_duration': 86627206961,
        'load_duration': 23585622554,
        'prompt_eval_duration': 3426000000,
        'eval_duration': 4799921000,
    }
    """
    meta = {key: value for key, value in input_response_dict.items() if key != "message"}

    if "done_reason" in meta:
        meta["finish_reason"] = ollama_cg.FINISH_REASON_MAPPING.get(meta.pop("done_reason") or "")
    if "created_at" in meta:
        meta["completion_start_time"] = meta.pop("created_at")
    if "eval_count" in meta and "prompt_eval_count" in meta:
        eval_count = meta.pop("eval_count")
        prompt_eval_count = meta.pop("prompt_eval_count")
        # The following line is the fix for eval_count or prompt_eval_count == None
        if isinstance(eval_count, int) and isinstance(prompt_eval_count, int):
            meta["usage"] = {
                "completion_tokens": eval_count,
                "prompt_tokens": prompt_eval_count,
                "total_tokens": eval_count + prompt_eval_count,
            }
    return meta


# Monkey patch fix for OllamaChatGenerator, ollama-haystack==5.1.0
def _thinking_convert_ollama_response_to_chatmessage(ollama_response: ChatResponse) -> ChatMessage:
    """
    Convert non-streaming Ollama Chat API response to Haystack ChatMessage with the assistant role.
    """
    response_dict = ollama_response.model_dump()
    ollama_message = response_dict["message"]
    text = ollama_message["content"]
    reasoning = ollama_message.get("thinking", None)
    if not text and reasoning:
        text = reasoning
        reasoning = None

    tool_calls: List[ToolCall] = []

    if ollama_tool_calls := ollama_message.get("tool_calls"):
        for ollama_tc in ollama_tool_calls:
            tool_calls.append(
                ToolCall(
                    tool_name=ollama_tc["function"]["name"],
                    arguments=ollama_tc["function"]["arguments"],
                )
            )

    chat_msg = ChatMessage.from_assistant(text=text or None, tool_calls=tool_calls, reasoning=reasoning)

    chat_msg._meta = _safe_convert_ollama_meta_to_openai_format(response_dict)

    return chat_msg

ollama_cg._convert_ollama_meta_to_openai_format = _safe_convert_ollama_meta_to_openai_format
ollama_cg._convert_ollama_response_to_chatmessage = _thinking_convert_ollama_response_to_chatmessage


def ollama_model_supports_thinking(ollama_host: str, ollama_model: str) -> bool:
    r = requests.post(f"http://{ollama_host}/api/chat", json={
        "model": ollama_model,
        "messages": [{"role": "user", "content": "ping"}],
        "think": True,
        "stream": False
    })
    data = r.json()
    supports_thinking = bool(data.get("message", {}).get("thinking"))
    return supports_thinking


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
        self.ollama_host = self.ollama_host or OLLAMA_HOST_DEFAULT
        if self.ollama_model or self.gemini_model or self.openai_model:
            return self
        if os.environ.get("GEMINI_API_KEY", None) or os.environ.get("GOOGLE_API_KEY", None):
            self.gemini_model = "gemini-flash-latest"
        elif os.environ.get("OPENAI_API_KEY", None):
            self.openai_model = "gpt-5-mini"
        else:
            self.ollama_model = "gpt-oss:20b"
        return self

    def apply_summarizing_default(self):
        self.ollama_host = self.ollama_host or OLLAMA_HOST_DEFAULT
        if self.ollama_model or self.gemini_model or self.openai_model:
            return self
        if os.environ.get("GEMINI_API_KEY", None) or os.environ.get("GOOGLE_API_KEY", None):
            self.gemini_model = "gemini-flash-lite-latest"
        elif os.environ.get("OPENAI_API_KEY", None):
            self.openai_model = "gpt-5-nano"
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
            return f"Ollama {self.ollama_model} at {self.ollama_host}"

    def create_chat_generator(self,
                              temperature: Optional[float] = None,
                              generation_kwargs: Optional[Dict[str, Any]] = None,
                              tools: Optional[Union[List[Tool], Toolset]] = None):
        if self.openai_model:
            logger.info("Using OpenAI chat with model %s", self.openai_model)
            if self.openai_model.startswith("o4-mini") or self.openai_model.startswith("gpt-5"):
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
            _generation_kwargs: Dict[str, Any] = {
                "temperature": temperature or self.temperature,
            }
            ollama_timeout = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
            ollama_think = ollama_model_supports_thinking(self.ollama_host, self.ollama_model)
            if ollama_think:
                # OllamaChatGenerator docs say the think parameter can be a bool or "low", "medium", "high", but the client only supports bool
                # https://huggingface.co/docs/inference-providers/guides/gpt-oss
                _generation_kwargs["effort"] = "high"
            logger.info("Using Ollama chat with model %s at %s", self.ollama_model, self.ollama_host)
            return OllamaChatGenerator(
                url="http://" + (self.ollama_host or OLLAMA_HOST_DEFAULT),
                model=self.ollama_model,
                timeout=ollama_timeout,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
                tools=tools,
                think=ollama_think,
            )
        else:
            raise NotImplementedError

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
            logger.info("Using Ollama generator with model %s at %s", self.ollama_model, self.ollama_host)
            return OllamaGenerator(
                url="http://" + (self.ollama_host or OLLAMA_HOST_DEFAULT),
                model=self.ollama_model,
                generation_kwargs=_generation_kwargs | (generation_kwargs or {}),
            )
        else:
            raise NotImplementedError

    @property
    def chat_message_retriever_last_k(self):
        if self.openai_model:
            return 50
        elif self.gemini_model:
            return 100
        elif self.ollama_model:
            if self.ollama_model.startswith("gpt-oss"):
                return 30
        return 20
