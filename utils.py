import argparse
import os
from pathlib import Path
from urllib.parse import ParseResult, urlparse
from typing import Optional, Generator, Dict, Any, Union, List

from haystack.components.generators import OpenAIGenerator
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.tools import Toolset
from haystack_integrations.components.generators.google_genai.chat.chat_generator import GoogleGenAIChatGenerator
from haystack_integrations.components.generators.ollama import OllamaChatGenerator, OllamaGenerator
from mcp import Resource, Tool
from pydantic import BaseModel, Field
from tldextract import tldextract


class HttpResource(BaseModel):
    score: Optional[float] = Field(description="Matching score, higher is better")
    url: str = Field(description="The URL for the HTTP resource")
    host: str = Field(description="The host name of the HTTP server")
    port: int = Field(description="The port of the HTTP server")
    domain: str = Field(description="The domain name of the HTTP server, built from the host name")
    status_code: int = Field(description="The HTTP status code for the response")
    method: str = Field(description="The HTTP method that was used to request the resource")
    resource: Optional[Resource] = Field(description="A link to the resource content")


def urlparse_ext(url: str) -> ParseResult:
    url_parsed = urlparse(url, 'http')
    if url_parsed.port:
        port = url_parsed.port
    elif url_parsed.scheme == "http":
        port = 80
    elif url_parsed.scheme == "https":
        port = 443
    else:
        port = -1
    return ParseResult(
        scheme=url_parsed.scheme,
        netloc=f"{url_parsed.hostname}:{port}",
        params=url_parsed.params,
        path=url_parsed.path,
        query=url_parsed.query,
        fragment=url_parsed.fragment
    )


def latest_mtime(db: Path) -> float:
    """
    Get the latest modified time of the database.
    :param db: path to the database.
    :return:  the latest modified time as a float.
    """
    return max(f.stat().st_mtime for f in db.rglob("*.sqlite3") if f.is_file())


def extract_domain(hostname: str) -> str:
    domain = tldextract.extract(hostname, include_psl_private_domains=True).top_domain_under_public_suffix
    if not domain:
        return '.'.join(hostname.split(".")[-2:])
    return domain


def add_generator_args(ap: argparse.ArgumentParser):
    ap.add_argument("--ollama-url", help="The URL for the Ollama service", default="http://localhost:11434", required=False)
    ap.add_argument("--ollama-model", help="Use Ollama with the specified model, must already be pulled", required=False)
    ap.add_argument("--gemini-model", help="Use Google Gemini with the specified model, API key must be in env var GOOGLE_API_KEY or GEMINI_API_KEY", required=False)
    ap.add_argument("--openai-model", help="Use OpenAI with the specified model, API key must be in env var OPENAI_API_KEY", required=False)


class GeneratorConfig(BaseModel):
    ollama_url: Optional[str] = Field(description="The URL of the OLLAMA server")
    ollama_model: Optional[str] = Field(description="The name of the OLLAMA model")
    gemini_model: Optional[str] = Field(description="The name of the GEMINI model")
    openai_model: Optional[str] = Field(description="The name of the OpenAI model")

    @staticmethod
    def from_args(args):
        generator_config = GeneratorConfig(
            ollama_url=args.ollama_url or os.environ.get("OLLAMA_URL", None),
            ollama_model=args.ollama_model or os.environ.get("OLLAMA_MODEL", None),
            gemini_model=args.gemini_model or os.environ.get("GEMINI_MODEL", None),
            openai_model=args.openai_model or os.environ.get("OPENAI_MODEL", None),
        )
        assert generator_config.ollama_model or generator_config.gemini_model or generator_config.openai_model
        return generator_config

    @staticmethod
    def from_env():
        generator_config = GeneratorConfig(
            ollama_url=os.environ.get("OLLAMA_URL", None),
            ollama_model=os.environ.get("OLLAMA_MODEL", None),
            gemini_model=os.environ.get("GEMINI_MODEL", None),
            openai_model=os.environ.get("OPENAI_MODEL", None),
        )
        return generator_config

    def create_chat_generator(self, generation_kwargs: Optional[Dict[str, Any]] = None, tools: Optional[Union[List[Tool], Toolset]] = None):
        if self.openai_model:
            return OpenAIChatGenerator(model=self.openai_model, generation_kwargs=generation_kwargs, tools=tools)
        elif self.gemini_model:
            return GoogleGenAIChatGenerator(model=self.gemini_model, generation_kwargs=generation_kwargs, tools=tools)
        elif self.ollama_model:
            if self.ollama_url:
                return OllamaChatGenerator(url=self.ollama_url, model=self.ollama_model, generation_kwargs=generation_kwargs, tools=tools)
            else:
                return OllamaChatGenerator(model=self.ollama_model, generation_kwargs=generation_kwargs, tools=tools)
        else:
            raise NotImplementedError

    def create_generator(self, generation_kwargs: Optional[Dict[str, Any]] = None):
        if self.openai_model:
            return OpenAIGenerator(model=self.openai_model, generation_kwargs=generation_kwargs)
        elif self.gemini_model:
            return GoogleGenAIChatGenerator(model=self.gemini_model, generation_kwargs=generation_kwargs)
        elif self.ollama_model:
            if self.ollama_url:
                return OllamaGenerator(url=self.ollama_url, model=self.ollama_model, generation_kwargs=generation_kwargs)
            else:
                return OllamaGenerator(model=self.ollama_model, generation_kwargs=generation_kwargs)
        else:
            raise NotImplementedError
