#!/usr/bin/env python3
import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from json import JSONDecodeError
from typing import Dict, List, Optional, Any, Tuple

from bs4 import BeautifulSoup, SoupStrainer
from chromadb import AsyncClientAPI
from haystack.components.agents import Agent
from haystack.components.joiners import ListJoiner
from haystack.components.preprocessors import DocumentCleaner
from haystack.components.routers import ConditionalRouter
from haystack.components.tools import ToolInvoker
from haystack.core.component import Component
from haystack.dataclasses import ChatMessage
from haystack.document_stores.types import DuplicatePolicy
from haystack.tools import Toolset
from haystack_experimental.chat_message_stores import InMemoryChatMessageStore
from haystack_experimental.components.retrievers import ChatMessageRetriever
from haystack_experimental.components.writers import ChatMessageWriter
from mcp import Tool
from more_itertools import first

from doc_type_model_map import get_model_for_doc_type, doc_type_to_model, map_mime_to_type

import mcp

import chromadb
from haystack_integrations.document_stores.chroma import ChromaDocumentStore
from haystack_integrations.components.retrievers.chroma import ChromaEmbeddingRetriever
from haystack.components.embedders import SentenceTransformersTextEmbedder, SentenceTransformersDocumentEmbedder
from haystack.components.builders import PromptBuilder, AnswerBuilder, ChatPromptBuilder
from haystack import Pipeline, component, Document
from haystack_integrations.tools.mcp import StreamableHttpServerInfo, MCPToolset

from prompts import pentester_agent_system_prompt, pentester_chat_system_prompt
from utils import urlparse_ext, GeneratorConfig, extract_domain

os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
os.environ['ANONYMIZED_TELEMETRY'] = "False"
os.environ['HAYSTACK_TELEMETRY_ENABLED'] = "False"
os.environ['HAYSTACK_TELEMETRY_DISABLED'] = "1"

logger = logging.getLogger(__name__)

# Change this when previously indexed data becomes obsolete
WEB_RESOURCE_VERSION = 1

async def create_chroma_client(db: str) -> AsyncClientAPI:
    if re.match(r'\S+:\d+$', db):
        host, _, port = db.rpartition(':')
        return await chromadb.AsyncHttpClient(host=host, port=int(port))
    return await chromadb.AsyncHttpClient(host="127.0.0.1", port=8200)


def create_chrome_document_store(db: str, **kwargs) -> ChromaDocumentStore:
    if re.match(r'\S+:\d+$', db):
        host, _, port = db.rpartition(':')
        return ChromaDocumentStore(host=host, port=int(port), **kwargs)
    return ChromaDocumentStore(host="127.0.0.1", port=8200, **kwargs)


async def list_collections(db: str) -> List[str]:
    """Return collection names using a raw Chroma client."""
    client = await create_chroma_client(db)
    return [c.name for c in (await client.list_collections())]


@component
class CombineDocs:
    def __init__(self, collections: list[str]) -> None:
        input_types = {k: List[Document] for k in collections}
        component.set_input_types(self, **input_types)

    @component.output_types(documents=List[Document])
    def run(self, **kwargs):
        try:
            ctx = mcp.get_context()
            ctx.info("Combining documents")
        except Exception:
            pass
        merged = []
        for docs in kwargs.values():
            merged.extend(docs)
        merged.sort(key=lambda d: d.score or 0, reverse=True)
        return {"documents": merged}


@component
class TraceDocs:
    """
    Stores queries and documents into a file for debugging.
    """

    def __init__(self, file: str | os.PathLike[str] = "trace_documents.md") -> None:
        self.file = file

    @component.output_types()
    def run(self, query: str, expanded_queries: List[str], documents: List[Document]):
        with open(self.file, "a", encoding="utf-8") as f:
            f.write(f"# Q: {query}\n\n")
            f.write(f"## Q expanded:\n")
            for eq in expanded_queries:
                f.write(f"- {eq}\n")
            f.write("\n")
            for doc in documents:
                f.write(f"## {doc.meta["url"]}\n")
                f.write(f"Score: {doc.score}\n\n")
                f.write(doc.content[0:1024])
                f.write(f"\n\n")
            f.write(f"\n\n---\n\n")
        return {}


@component
class Query:
    @component.output_types(text=str, filters=Dict[str, Any], max_results=int)
    def run(self, text: str, filters: Optional[Dict[str, Any]] = None, max_results: Optional[int] = None):
        max_results = min(1000, max(1, max_results or 100))
        return {"text": text, "filters": filters or {}, "max_results": max_results}


query_expander_natural_language = """
You are a cybersecurity search assistant that processes users queries.
You expand a given query into at most {{ number }} queries that are similar in meaning. The expanded query should not be less specific. All URLs or IP addresses that appear in the original query must be included in the expanded query.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. Do not include any other text except the JSON list of expanded queries.
Examples:
1. Example Query 1: "cross-site scripting mitigation"  
   Example Expanded Queries: ["XSS prevention techniques", "sanitizing user input", "reflected XSS protection", "stored XSS defense"]

2. Example Query 2: "SQL injection exploitation"  
   Example Expanded Queries: ["union-based SQL injection", "blind SQLi attack", "SQLMap usage examples", "database extraction via SQLi"]          
Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

query_expander_javascript = """
You are a cybersecurity search assistant that processes users queries. You are specialized in JavaScript
programming, securing coding in JavaScript, and obfuscation techniques.
You expand a given query into at most {{ number }} queries that are example JavaScript snippets that are an interpretation of the given query. Never include console.log(). Do not include the target hostname or IP address.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. The values must only be JavaScript code. Do not include any other text except the JSON list of expanded queries. Exclude expanded queries that are only whitespace.

Examples:
1. Example Query 1: "What javascript libraries call eval()"
   Example Expanded Queries: ["Object.prototype.eval = function() {\n return eval(this);\n};", "window.eval = function(code) {\n return eval(code);\n};", "Function.prototype.customEval = function(code) {\n return eval(code);\n}"]
1. Example Query 1: "Find Javascript libraries on http://2million.htb"
   Example Expanded Queries: ["fetch('/libraries').then(res => res.json()).then(data => data.map(lib => lib.name))","axios.get('/libraries').then(response => response.data.map(lib => lib.name))","new XMLHttpRequest().open('GET', '/libraries', true).send(), new Promise((resolve) => { resolve(xhr.responseXML.getElementsByTagName('library').textContent.split(', ')); })","$.ajax({url: '/libraries', success: function(data){ $.each($(data).find('.library'), function(index, lib){ console.log($(lib).text()); }); }})","fetch('/libraries').then(res => res.text()).then(html => Array.from(new DOMParser().parseFromString(html, 'text/html').getElementsByTagName('a')).map(a => a.textContent))"]

Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

query_expander_css = """
You are a cybersecurity search assistant that processes users queries. You are specialized in style sheet
development and securing CSS.
You expand a given query into at most {{ number }} queries that are example CSS snippets that are an interpretation of the given query. Do not include the target hostname or IP address.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. The values must only be CSS code. Do not include any other text except the JSON list of expanded queries. Exclude expanded queries that are only whitespace.

Examples:
1. Example Query 1: "Find CSS vulns"
   Example Expanded Queries: ["x-allow-cross-origin-resource-sharing: *;\n@font-face { src: url(‘http://attacker.com/malware.ttf’); }\ninput[type=‘text’] { content: url(‘http://attacker.com/hack.jpg’); }"]

Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

query_expander_html = """
You are a cybersecurity search assistant that processes users queries. You are specialized in HTML
development and securing HTML.
You expand a given query into at most {{ number }} queries that are example HTML snippets that are an interpretation of the given query. Do not include the target hostname or IP address.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. The values must only be HTML code. Do not include any other text except the JSON list of expanded queries. Exclude expanded queries that are only whitespace.

Examples:
1. Example Query 1: "Find CSS vulns"
   Example Expanded Queries: ["x-allow-cross-origin-resource-sharing: *;\n@font-face { src: url(‘http://attacker.com/malware.ttf’); }\ninput[type=‘text’] { content: url(‘http://attacker.com/hack.jpg’); }"]

Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

query_expander_xml = """
You are a cybersecurity search assistant that processes users queries. You are specialized in XML
development and securing XML.
You expand a given query into at most {{ number }} queries that are example XML snippets that are an interpretation of the given query.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. The values must only be XML code. Do not include any other text except the JSON list of expanded queries. Exclude expanded queries that are only whitespace.

Examples:
1. Example Query 1: "Find <docs>...</docs>"
   Example Expanded Queries: ["<docs>...</docs>"]

Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

query_expander_network = """
You are a cybersecurity search assistant that processes users queries. You are specialized in the security of the HTTP protocol and vulnerabilities associated with HTTP.
You expand a given query into at most {{ number }} queries that are snippets of things in HTTP like headers and response codes.

Structure:
Output the expanded queries as a valid JSON list of strings. Only output the list. The values must only be XML code. Do not include any other text except the JSON list of expanded queries. Exclude expanded queries that are only whitespace.

Examples:
1. Example Query 1: "Examine the CSP"
   Example Expanded Queries: ["Content-Security-Policy:"]
2. Example Query 1: "Look for vulnerable cookie settings"
   Example Expanded Queries: ["Set-Cookie: samesite=None", "Set-Cookie: domain="]

Your Task:
Query: "{{query}}"
Example Expanded Queries:
"""

@component
class QueryExpander:
    def __init__(self, generator_config: GeneratorConfig, prompt: Optional[str] = None, number: int = 5):

        self.query_expansion_prompt = prompt
        self.number = number
        if prompt is None:
            self.query_expansion_prompt = query_expander_natural_language
        builder = PromptBuilder(self.query_expansion_prompt, required_variables=["number", "query"])
        llm = generator_config.create_generator()
        self.pipeline = Pipeline()
        self.pipeline.add_component(name="builder", instance=builder)
        self.pipeline.add_component(name="llm", instance=llm)
        self.pipeline.connect("builder", "llm")

    @component.output_types(queries=List[str])
    def run(self, query: str):
        if self.number <= 1:
            return {"queries": [query]}
        try:
            ctx = mcp.get_context()
            ctx.info(f"Expanding query")
        except Exception:
            pass
        result = \
            self.pipeline.run({'builder': {'query': query, 'number': self.number}}).get('llm', {}).get('replies', [""])[
            0]
        logger.info(f"Expanded query result:\n{result}")
        if not result:
            return {"queries": [query]}
        try:
            expanded_list = [query]
            expanded_json = json.loads(result)
            if isinstance(expanded_json, list):
                expanded_list.extend(list(map(
                    lambda e: first(e.values()) if isinstance(e, dict) else str(e),
                    expanded_json)))
            expanded_list = list(filter(bool, expanded_list))
            return {"queries": expanded_list}
        except JSONDecodeError:
            return {"queries": [query]}


@component
class MultiQueryChromaRetriever:
    def __init__(self, embedder: SentenceTransformersTextEmbedder, retriever: ChromaEmbeddingRetriever):
        self.embedder = embedder
        self.retriever = retriever

    def warm_up(self):
        self.embedder.warm_up()

    @component.output_types(documents=List[Document])
    def run(self, queries: List[str], top_k: int, filters: Optional[Dict[str, Any]] = None):
        try:
            ctx = mcp.get_context()
            ctx.info("Retrieving documents")
        except Exception:
            pass
        top_k = min(1000, max(1, top_k))
        results = []
        ids = set()
        for query in queries:
            logger.info(f"Query: {query}")
            try:
                result = self.retriever.run(
                    query_embedding=self.embedder.run(query)["embedding"],
                    filters=filters,
                    top_k=top_k)
                for doc in result['documents']:
                    if doc.id not in ids:
                        results.append(doc)
                        ids.add(doc.id)
            except Exception as e:
                logger.error(f"Exception querying chroma database: {str(e)}", exc_info=e)
        results.sort(key=lambda x: x.score, reverse=True)
        return {"documents": results}


def _create_tools(mcp_urls: Optional[List[str]] = None) -> Toolset:
    if mcp_urls is None:
        mcp_urls = ["http://127.0.0.1:8000/mcp/"]
    if len(mcp_urls) == 1:
        return MCPToolset(
            server_info=StreamableHttpServerInfo(url=mcp_urls[0]),
            invocation_timeout=600.0
        )
    tools = []
    for mcp_url in mcp_urls:
        tools.extend(list(MCPToolset(
            server_info=StreamableHttpServerInfo(url=mcp_url),
            invocation_timeout=600.0
        )))
    return Toolset(tools=tools)


user_chat_message_template = """Given the conversation history, complete the task requested.

    Conversation history:
    {% for memory in memories %}
        {{ memory.text }}
    {% endfor %}

    Task: {{query}}
"""


def build_chat_pipeline(generator_config: GeneratorConfig, mcp_urls: Optional[List[str]] = None) -> Tuple[
    Pipeline, Component, List[Tool]]:
    """
    Builds a pipeline for a cyber-security chat.
    :return: Pipeline, generator component
    """

    tools = _create_tools(mcp_urls)
    prompt_builder = ChatPromptBuilder(
        template=[ChatMessage.from_system(pentester_chat_system_prompt), ChatMessage.from_user(user_chat_message_template)],
        variables=["query", "memories"],
        required_variables=["query", "memories"]
    )
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={}
    )
    response_chat_generator = generator_config.create_chat_generator(
        generation_kwargs={}
    )

    memory_store = InMemoryChatMessageStore()
    memory_retriever = ChatMessageRetriever(memory_store, last_k=15)
    memory_writer = ChatMessageWriter(memory_store)

    pipeline = Pipeline()
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("llm", chat_generator)
    pipeline.add_component("tool_invoker", ToolInvoker(tools=tools))
    pipeline.add_component("list_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("memory_retriever", memory_retriever)
    pipeline.add_component("memory_writer", memory_writer)
    pipeline.add_component("memory_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("response_llm", response_chat_generator)

    pipeline.connect("prompt_builder.prompt", "llm.messages")
    pipeline.connect("llm.replies", "tool_invoker.messages")
    pipeline.connect("llm.replies", "list_joiner")
    pipeline.connect("llm.replies", "memory_joiner")
    pipeline.connect("tool_invoker.tool_messages", "list_joiner")
    pipeline.connect("list_joiner.values", "response_llm.messages")

    pipeline.connect("memory_joiner", "memory_writer")
    pipeline.connect("memory_retriever", "prompt_builder.memories")

    return pipeline, response_chat_generator, tools


@component
class ChatMessageToListAdapter:
    @component.output_types(values=List[ChatMessage])
    def run(self, value: ChatMessage):
        return {"values": [value]}


def build_agent_pipeline(generator_config: GeneratorConfig, mcp_urls: Optional[List[str]] = None) -> Tuple[
    Pipeline, Component, List[Tool]]:
    """
    Builds a pipeline for a cyber-security agent.
    :return: Pipeline
    """

    tools = _create_tools(mcp_urls)
    prompt_builder = ChatPromptBuilder(
        template=[ChatMessage.from_user(user_chat_message_template)],
        variables=["query", "memories"],
        required_variables=["query", "memories"]
    )
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={}
    )
    assistant = Agent(
        chat_generator=chat_generator,
        tools=tools,
        system_prompt=pentester_agent_system_prompt,
        exit_conditions=["text"],
        max_agent_steps=100,
        raise_on_tool_invocation_failure=False
    )

    memory_store = InMemoryChatMessageStore()
    memory_retriever = ChatMessageRetriever(memory_store)
    memory_writer = ChatMessageWriter(memory_store)

    pipeline = Pipeline()
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("agent", assistant)
    pipeline.add_component("memory_retriever", memory_retriever)
    pipeline.add_component("memory_writer", memory_writer)
    pipeline.add_component("memory_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("str_to_list", ChatMessageToListAdapter())

    pipeline.connect("prompt_builder", "agent")

    pipeline.connect("agent.last_message", "str_to_list")
    pipeline.connect("str_to_list", "memory_joiner")
    pipeline.connect("memory_joiner", "memory_writer")
    pipeline.connect("memory_retriever", "prompt_builder.memories")

    return pipeline, assistant, tools


async def build_document_pipeline(db: str, generator_config: GeneratorConfig) -> Tuple[
    Pipeline, Dict[str, MultiQueryChromaRetriever], Dict[str, ChromaDocumentStore]]:
    """
    Builds a pipeline for retrieving documents from the store.
    :param db: path to the database.
    :return: Pipeline
    """
    collections = doc_type_to_model.keys()

    pipe = Pipeline()
    comb = CombineDocs([f"{col}_documents" for col in collections])
    pipe.add_component("combine", comb)
    pipe.add_component("query", Query())
    pipe.add_component("query_expander", QueryExpander(generator_config))
    pipe.connect("query.text", "query_expander.query")

    retrievers: Dict[str, MultiQueryChromaRetriever] = {}
    stores: Dict[str, ChromaDocumentStore] = {}

    for col in collections:
        model_name = get_model_for_doc_type(col)

        store = create_chrome_document_store(db=db, collection_name=col)
        stores[col] = store
        embedder = SentenceTransformersTextEmbedder(model=model_name, progress_bar=False)
        retriever = ChromaEmbeddingRetriever(document_store=store)
        multiquery_retriever = MultiQueryChromaRetriever(embedder, retriever)
        retrievers[col] = multiquery_retriever

        ret_name = f"ret_{col}"
        pipe.add_component(ret_name, multiquery_retriever)

        custom_query_expander = None
        if col == "javascript":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_javascript, number=10)
        elif col == "css":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_css, number=5)
        elif col == "html":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_html, number=10)
        elif col == "xml":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_xml, number=5)
        elif col == "network":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_network, number=5)

        # wiring: Query → embedder → retriever → combiner
        pipe.connect("query.max_results", ret_name + ".top_k")
        if custom_query_expander is not None:
            pipe.add_component("query_expander_"+col, custom_query_expander)
            pipe.connect("query.text", "query_expander_"+col+".query")
            pipe.connect("query_expander_"+col+".queries", ret_name + ".queries")
        else:
            pipe.connect("query_expander.queries", ret_name + ".queries")
        pipe.connect("query.filters", ret_name + ".filters")
        pipe.connect(ret_name + ".documents", f"combine.{col}_documents")

    # pipe.add_component("trace_docs", TraceDocs())
    # pipe.connect("query.text", "trace_docs.query")
    # pipe.connect("query_expander.queries", "trace_docs.expanded_queries")
    # pipe.connect("combine.documents", "trace_docs.documents")

    return pipe, retrievers, stores


def build_website_context_pipeline(generator_config: GeneratorConfig) -> Pipeline:
    prompt = """
      You are a cybersecurity search assistant that processes users queries for websites.
      You determine the site url(s) and/or ip address(es) and ports the user is interested in. You
      also determine optional types of content the user is interested in from the following list:
      "html", "forms", "xml", "javascript", "css", "json", "network". If the query includes things that would be in the HTTP headers such as cookies or the content security policy include the content type "network".
      You also determine technology stacks the user references, if any.
      You also determine if anything in the query implies a specific set of HTTP response codes, if any. Be cautious about providing methods so to not be too limiting.
      You also determine if anything in the query implies a specific set of HTTP methods such as "GET", "POST", "PUT", if any. Usually the user will intended HTTP methods that are in the RFC, but may ask for specific non-standard methods.
      
      Structure:
      Output the information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      
      The list of web sites uses key "target". The value of "target" is a valid JSON list. It is a list of site url(s) or ip address(es) and port numbers in the form of URLs. If no protocol is specified and the port contains "443", use "https". If no protocol is specified and the url host TLD is typically for a public site like .com, .net, .etc, use protocol "https". Otherwise use "http". 
      Examples are: http://example.com, https://example.com, http://example.com:8080, http://10.10.10.10, http://10.10.10.11:8000, etc.

      The list of content types uses key "content". The value of "content" is a valid JSON list. Only use the aforementioned list of content types.

      The list of technology uses key "tech". The value of "tech" is a valid JSON list. Prefer using the format of "name/version".

      The list of HTTP methods uses key "methods". The value of "methods" is a valid JSON list of upper case alphanumeric strings.

      The list of HTTP response codes uses key "response_codes". The value of "response_codes" is a valid JSON list of integers.

      Examples:
        1. Example Query 1: "Examine http://example.com for vulns"  
           Example Result: {"target": ["http://example.com"], "content": [], "tech": [], "methods": [], "response_codes": []}

        2. Example Query 2: "Examine 10.10.10.10:8000 for risky javascript functions"  
           Example Result: {"target": ["http://10.10.10.10:8000"], "content": ["javascript"], "tech": [], "methods": [], "response_codes": []}

        3. Example Query 3: "Examine nobody.net for vulnerable versions of WordPress"  
           Example Result: {"target": ["https://nobody.net"], "content": [""], "tech": ["WordPress"], "methods": [], "response_codes": []}

        4. Example Query 4: "Examine authentication failures on schooldaze.edu for username disclosure"
           Example Result: {"target": ["https://schooldaze.edu"], "content": [""], "tech": [""], "methods": [], "response_codes": [403]}

        5. Example Query 5: "Examine posted forms on 192.168.1.1:8090 for XSS vulns."
           Example Result: {"target": ["http://192.168.1.1:8090"], "content": [""], "tech": [""], "methods": ["POST"], "response_codes": []}

      Your Task:
      Query: "{{query}}"
      JSON targets, optional content, optional tech:
      """
    builder = PromptBuilder(prompt, required_variables=["query"])
    llm = generator_config.create_generator()
    pipeline = Pipeline()
    pipeline.add_component(name="builder", instance=builder)
    pipeline.add_component(name="llm", instance=llm)
    pipeline.connect("builder", "llm")
    return pipeline


def is_binary(content: str, mime_type: str) -> bool:
    """
    Detect if the content is binary based on the raw MIME type and content.
    """
    mime_category = mime_type.split("/")[0]
    if mime_category in [
        "video",
        "audio",
        "font",
    ]:
        return True
    if mime_type in [
        "application/octet-stream",
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/jpg",
        "image/webp",
        "application/pdf",
        "application/x-pdf",
        "application/zip",
        "application/x-zip-compressed",
    ]:
        return True
    if not content.strip():
        return False
    try:
        sample = content.encode("utf-8", errors="ignore")[:1024]
        if not sample:
            return False
        high = sum(b > 127 for b in sample)
        low = sum(b <= 127 for b in sample)
        return high > 0.15 * max(low, 1)
    except Exception:
        return False


def _deobfuscate_javascript(content: str) -> str:
    if not content:
        return content

    docker_command = ["docker", "run", "--rm", "-i", "shyhurricane_unix_command:latest", '/usr/share/wakaru/wakaru.cjs']
    logger.info(f"Deobfuscating javascript with command {' '.join(docker_command)}")
    proc = subprocess.Popen(docker_command, universal_newlines=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    result = ""
    try:
        proc.stdin.write(content)
        proc.stdin.close()
        while proc.poll() is None:
            line_out = proc.stdout.readline()
            if line_out:
                result += line_out
        # read any buffered output
        while True:
            line_out = proc.stdout.readline()
            if not line_out:
                break
            result += line_out
    except EOFError:
        pass

    return_code = proc.wait()
    if return_code != 0 or not result.strip():
        logger.error("Deobfuscating javascript failed with exit code %d", return_code)
        return content
    else:
        logger.info("Deobfuscating javascript completed, from %d bytes to %d bytes", len(content), len(result))
        return result


@component
class KatanaDocument:
    def __init__(self, embedders: Dict[str, Any], doc_cleaner: DocumentCleaner):
        self.embedders = embedders
        self.doc_cleaner = doc_cleaner
        self._title_soup_strainer = SoupStrainer(['title', 'meta'])

    @component.output_types(documents=List[Document])
    def run(self, text: str | dict):
        if isinstance(text, dict):
            entry = text
        else:
            entry = json.loads(str(text))
        if "request" not in entry:
            logger.warning("Missing request")
            return {"documents": []}
        if "response" not in entry:
            logger.warning("Missing response")
            return {"documents": []}
        if "status_code" not in entry["response"]:
            logger.info("No status_code, usually indicates out of scope")
            return {"documents": []}

        url = entry["request"]["endpoint"]
        try:
            url_parsed = urlparse_ext(url)
            host = url_parsed.hostname.lower()
            port = url_parsed.port
            netloc = f"{host}:{port}"
            domain = extract_domain(host)
        except Exception:
            logger.warning(f"Malformed URL: {url}")
            return {"documents": []}

        # quantize timestamp to avoid too many duplicate results
        timestamp = entry["timestamp"]  # 2025-06-28T22:52:07.882000
        timestamp_for_id = timestamp[0:11]  # one document per URL per day
        response_body: Optional[str] = entry.get("response", {}).get("body", None)
        status_code = entry["response"].get("status_code", 200)
        http_method = entry["request"].get("method", "").upper()
        request_headers = entry["request"].get("headers", {})
        request_headers.pop("raw", None)
        response_headers = entry["response"].get("headers", {})
        response_headers.pop("raw", None)
        raw_mime = response_headers.get("content-type", response_headers.get("content_type", "")).lower().split(";")[
            0].strip()
        technologies = entry["response"].get("technologies", [])
        if not isinstance(technologies, list):
            technologies = [str(technologies)]
        technologies_str = json.dumps(technologies, indent=None, separators=(',', ':'), sort_keys=True)

        title: Optional[str] = None
        description: Optional[str] = None
        if response_body and raw_mime == "text/html":
            soup = BeautifulSoup(response_body, 'html.parser', parse_only=self._title_soup_strainer)

            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            else:
                # Try fallback meta tags in priority order
                title_fallbacks = [
                    ('property', 'og:title'),
                    ('name', 'twitter:title'),
                    ('itemprop', 'name'),
                ]
                for attr, value in title_fallbacks:
                    tag = soup.find('meta', attrs={attr: value})
                    if tag and tag.get('content', ''):
                        title = tag['content'].strip()
                        break

            # extract description
            for meta in soup.find_all('meta'):
                attrs = meta.attrs
                meta_content = attrs.get('content', '')
                if not meta_content:
                    continue

                if attrs.get('name') == 'description':
                    description = meta_content.strip()
                elif attrs.get('property') == 'og:description':
                    description = meta_content.strip()
                elif attrs.get('name') == 'twitter:description':
                    description = meta_content.strip()
                elif attrs.get('itemprop') == 'description':
                    description = meta_content.strip()

        base_meta = {
            "version": WEB_RESOURCE_VERSION,
            "url": url,
            "netloc": netloc,
            "host": host,
            "port": port,
            "domain": domain,
            "timestamp": timestamp,
            "content_type": raw_mime,
            "status_code": status_code,
            "http_method": http_method,
            "technologies": technologies_str,
        }
        if title:
            base_meta["title"] = title
        if description:
            base_meta["description"] = description

        documents = []

        # Map MIME to a logical doc type
        doc_type = map_mime_to_type(raw_mime)

        run_cleaner = True
        if doc_type == "javascript" and response_body:
            response_body = _deobfuscate_javascript(response_body)
            response_headers["content_length"] = str(len(response_body))
            run_cleaner = False

        content = response_body

        # ─ Content Document (if body is present)
        if response_body and not is_binary(response_body, raw_mime):
            doc = Document(
                content=response_body,
                meta=base_meta | {
                    "type": "content",
                    "request_headers": json.dumps(request_headers),
                    "response_headers": json.dumps(response_headers),
                },
                id=hashlib.sha256(f"{url}:content:{timestamp_for_id}".encode()).hexdigest()
            )
            embedder = self.embedders.get("content", self.embedders["default"])
            documents.extend(embedder.run(documents=[doc])["documents"])

        # ─ Type specific Document (if body is present)
        if content:
            if is_binary(content, raw_mime):
                logger.info(f"[-] Skipping {url} ({raw_mime}) binary content")
            else:
                doc = Document(
                    content=content,
                    meta=base_meta | {"type": doc_type},
                    id=hashlib.sha256(f"{url}:{doc_type}:{timestamp_for_id}".encode()).hexdigest()
                )
                try:
                    if run_cleaner:
                        doc = self.doc_cleaner.run(documents=[doc])["documents"][0]
                except Exception:
                    logger.warning(f"[-] Content cleaning failed, continuing with original content")
                embedder = self.embedders.get(doc_type, self.embedders["default"])
                documents.extend(embedder.run(documents=[doc])["documents"])

        # ─ Network Document (always)
        sorted_request_headers = "\n".join(
            f"{k.replace('_', '-').title()}: {v}" for k, v in sorted(request_headers.items())
        )
        sorted_response_headers = "\n".join(
            f"{k.replace('_', '-').title()}: {v}" for k, v in sorted(response_headers.items())
        )
        net_text = (
                "--- HTTP Request Headers ---\n" +
                sorted_request_headers +
                "\n--- HTTP Response Headers ---\n" +
                sorted_response_headers
        )

        net_doc = Document(
            content=net_text,
            meta=base_meta | {
                "type": "network",
                "description": "HTTP request and response headers",
                "content_type": "text/plain"
            },
            id=hashlib.sha256(f"{url}:network:{timestamp_for_id}".encode()).hexdigest()
        )
        net_embedder = self.embedders["network"]
        documents.extend(net_embedder.run(documents=[net_doc])["documents"])

        # ─ HTML forms
        if "forms" in entry["response"]:
            forms = entry["response"]["forms"]
            sorted_forms = sorted(forms, key=lambda f: f.get("method", "GET") + "." + f.get("action", ""))
            forms_doc = Document(
                content=json.dumps(sorted_forms, indent=None, separators=(',', ':'), sort_keys=True),
                meta=base_meta | {
                    "type": "forms",
                    "description": "HTTP form information in JSON format",
                    "content_type": "text/json"
                },
                id=hashlib.sha256(f"{url}:forms:{timestamp_for_id}".encode()).hexdigest()
            )
            forms_embedder = self.embedders["forms"]
            documents.extend(forms_embedder.run(documents=[forms_doc])["documents"])

        return {"documents": documents}


@component
class HttpRawDocument:
    def __init__(self, embedders: Dict[str, Any], doc_cleaner: DocumentCleaner):
        self.embedders = embedders
        self.doc_cleaner = doc_cleaner

    @component.output_types(documents=List[Document])
    def run(self, text: str):
        return {"documents": []}


@component
class HarDocument:
    def __init__(self, embedders: Dict[str, Any], doc_cleaner: DocumentCleaner):
        self.embedders = embedders
        self.doc_cleaner = doc_cleaner

    @component.output_types(documents=List[Document])
    def run(self, text: str):
        return {"documents": []}


@component
class IngestMultiStore:
    def __init__(self, stores: Dict[str, ChromaDocumentStore]):
        self.stores = stores

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        for doc in documents:
            self.stores.get(doc.meta.get('type')).write_documents([doc], policy=DuplicatePolicy.OVERWRITE)
        return {"documents": documents}


@component
class GenerateTitleAndDescription:
    prompt: str = """
      You are a web site content analyst. You are good at summarizing the content of a web resource, whether it be
      HTML, text, javascript or css, into a short title and 2-3 sentence description. The consumer of the title and
      description is another LLM such as yourself.
      
      Structure:
      Output the title and description information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      
      The title uses the key "title" and the value is a string. It should be between 5 and 30 words long.
      
      The description uses the key "description" and the value is a string. It should be about 2 or 3 sentences.

      Your Task:
      Query: "%s"
      JSON title and description:
"""

    def __init__(self, generator_config: GeneratorConfig):
        self.generator = generator_config.create_generator()

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        cached_title = {}
        cached_description = {}
        for doc in documents:
            if doc.meta.get("status_code", 0) != 200:
                continue
            if doc.meta.get("type") in ["network"]:
                continue
            url = None
            if 'url' in doc.meta:
                url = doc.meta["url"]
                if url in cached_title and "title" not in doc.meta:
                    doc.meta["title"] = cached_title[url]
                if url in cached_description and "description" not in doc.meta:
                    doc.meta["description"] = cached_description[url]
            if doc.content and "title" not in doc.meta or "description" not in doc.meta:
                try:
                    result = self.generator.run(prompt=self.prompt % (doc.content[0:2048])).get("replies", ["{}"])[-1]
                    parsed = json.loads(result)
                    print(f"title_and_desc: {doc.meta.get('type', '')} {result}", file=sys.stderr)
                    if "title" in parsed and "title" not in doc.meta:
                        doc.meta["title"] = str(parsed["title"])
                        if url:
                            cached_title[url] = doc.meta["title"]
                    if "description" in parsed and "description" not in doc.meta:
                        doc.meta["description"] = str(parsed["description"])
                        if url:
                            cached_description[url] = doc.meta["description"]
                except Exception:
                    pass

        return {"documents": documents}


def is_katana_jsonl(value: str):
    try:
        data = json.loads(value)
        if "request" not in data or "response" not in data or "timestamp" not in data:
            return False
        return "endpoint" in data["request"]
    except Exception:
        return False


def is_har_json(value: str):
    try:
        data = json.loads(value)
        if "log" not in data:
            return False
        return "entries" in data["log"]
    except Exception:
        return False


http_request_re = re.compile(
    r"^[A-Z][A-Z]+ [^\r\n]+ HTTP/[0-9][0-9.]*$",
    re.MULTILINE
)

http_response_re = re.compile(
    r"^HTTP/[0-9][0-9.]* \d{3} .+",
    re.MULTILINE
)


def is_http_raw(value: str):
    try:
        return bool(http_request_re.search(value) and http_response_re.search(value))
    except Exception:
        return False


def build_ingest_pipeline(db: str, generator_config: GeneratorConfig) -> Pipeline:
    if ":" not in db:
        os.makedirs(db, exist_ok=True)

    stores = {}
    embedders = {}
    for dtype, model_name in doc_type_to_model.items():
        embedder = SentenceTransformersDocumentEmbedder(
            model=model_name,
            progress_bar=False)
        embedder.warm_up()
        document_store = create_chrome_document_store(
            db=db,
            collection_name=dtype,
        )
        document_store.count_documents()  # ensure the collection exists
        stores[dtype] = document_store
        embedders[dtype] = embedder

    doc_cleaner = DocumentCleaner(
        keep_id=True,
        remove_empty_lines=True,
        remove_extra_whitespaces=True,
        unicode_normalization='NFKC',
        # ascii_only=True,
    )

    pipe = Pipeline()

    routes = [
        {
            "condition": "{{ text|is_katana_jsonl }}",
            "output": ["{{ text }}"],
            "output_name": ["katana_jsonl"],
            "output_type": [str],
        },
        {
            "condition": "{{ text|is_har_json }}",
            "output": ["{{ text }}"],
            "output_name": ["har_json"],
            "output_type": [str],
        },
        {
            "condition": "{{ text|is_http_raw }}",
            "output": ["{{ text }}"],
            "output_name": ["http_raw_text"],
            "output_type": [str],
        },
        # ConditionalRouter will fail if a path isn't taken
        {
            "condition": "{{ True }}",
            "output": ["{{ text }}"],
            "output_name": ["input_failure"],
            "output_type": [str],
        },
    ]
    custom_filters = {
        "is_katana_jsonl": is_katana_jsonl,
        "is_har_json": is_har_json,
        "is_http_raw": is_http_raw,
    }

    pipe.add_component("input_router", ConditionalRouter(routes=routes, custom_filters=custom_filters))
    pipe.add_component("katana_document", KatanaDocument(embedders=embedders, doc_cleaner=doc_cleaner))
    pipe.add_component("raw_document", HttpRawDocument(embedders=embedders, doc_cleaner=doc_cleaner))
    pipe.add_component("har_document", HarDocument(embedders=embedders, doc_cleaner=doc_cleaner))
    pipe.add_component("katana_store", IngestMultiStore(stores))
    pipe.add_component("raw_store", IngestMultiStore(stores))
    pipe.add_component("har_store", IngestMultiStore(stores))
    pipe.add_component("katana_gen_title", GenerateTitleAndDescription(generator_config))
    pipe.add_component("raw_gen_title", GenerateTitleAndDescription(generator_config))
    pipe.add_component("har_gen_title", GenerateTitleAndDescription(generator_config))

    pipe.connect("input_router.katana_jsonl", "katana_document.text")
    pipe.connect("input_router.http_raw_text", "raw_document.text")
    pipe.connect("input_router.har_json", "har_document.text")

    pipe.connect("katana_document", "katana_gen_title")
    pipe.connect("raw_document", "raw_gen_title")
    pipe.connect("har_document", "har_gen_title")

    pipe.connect("katana_gen_title", "katana_store")
    pipe.connect("raw_gen_title", "raw_store")
    pipe.connect("har_gen_title", "har_store")

    return pipe
