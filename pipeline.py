#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import re
from json import JSONDecodeError
from typing import Dict, List, Optional, Any, Tuple

from haystack.components.agents import Agent
from haystack.components.joiners import ListJoiner
from haystack.components.preprocessors import DocumentCleaner
from haystack.components.routers import ConditionalRouter
from haystack.components.tools import ToolInvoker
from haystack.core.component import Component
from haystack.dataclasses import ChatMessage
from haystack.tools import Toolset
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

from utils import urlparse_ext, GeneratorConfig, extract_domain

os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
os.environ['ANONYMIZED_TELEMETRY'] = "False"
os.environ['HAYSTACK_TELEMETRY_ENABLED'] = "False"
os.environ['HAYSTACK_TELEMETRY_DISABLED'] = "1"

logger = logging.getLogger(__name__)


def list_collections(db_path: str) -> List[str]:
    """Return collection names using a raw Chroma client."""
    client = chromadb.PersistentClient(path=db_path)
    return [c.name for c in client.list_collections()]


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
    @component.output_types(text=str, filters=Dict[str, Any])
    def run(self, text: str, filters: Optional[Dict[str, Any]] = None):
        return {"text": text, "filters": filters or {}}


@component
class QueryExpander:
    def __init__(self, generator_config: GeneratorConfig, prompt: Optional[str] = None):

        self.query_expansion_prompt = prompt
        if prompt is None:
            self.query_expansion_prompt = """
          You are a cybersecurity search assistant that processes users queries.
          You expand a given query into at most {{ number }} queries that are similar in meaning. The expanded query should not be less specific.
          
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
        builder = PromptBuilder(self.query_expansion_prompt, required_variables=["number", "query"])
        llm = generator_config.create_generator()
        self.pipeline = Pipeline()
        self.pipeline.add_component(name="builder", instance=builder)
        self.pipeline.add_component(name="llm", instance=llm)
        self.pipeline.connect("builder", "llm")

    @component.output_types(queries=List[str])
    def run(self, query: str, number: int = 5):
        if number <= 1:
            return {"queries": [query]}
        try:
            ctx = mcp.get_context()
            ctx.info(f"Expanding query")
        except Exception:
            pass
        result = self.pipeline.run({'builder': {'query': query, 'number': number}}).get('llm', {}).get('replies', [""])[0]
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
            return {"queries": expanded_list}
        except JSONDecodeError:
            return {"queries": [query]}


@component
class MultiQueryChromaRetriever:
    def __init__(self, embedder: SentenceTransformersTextEmbedder, retriever: ChromaEmbeddingRetriever, top_k: int = 3):
        self.embedder = embedder
        self.retriever = retriever
        self.top_k = top_k

    def warm_up(self):
        self.embedder.warm_up()

    @component.output_types(documents=List[Document])
    def run(self, queries: List[str], filters: Optional[Dict[str, Any]] = None):
        try:
            ctx = mcp.get_context()
            ctx.info("Retrieving documents")
        except Exception:
            pass
        results = []
        ids = set()
        for query in queries:
            logger.info(f"Query: {query}")
            try:
                result = self.retriever.run(
                    query_embedding=self.embedder.run(query)["embedding"],
                    filters=filters,
                    top_k=self.top_k)
                for doc in result['documents']:
                    if doc.id not in ids:
                        results.append(doc)
                        ids.add(doc.id)
            except Exception as e:
                logger.error(f"Exception querying chroma database: {str(e)}", exc_info=e)
        results.sort(key=lambda x: x.score, reverse=True)
        return {"documents": results}


def build_answer_pipeline(db: str, generator_config: GeneratorConfig, top_k: int) -> Tuple[Pipeline, Component]:
    """
    Builds a pipeline for making security related queries.
    :param db: path to the database.
    :param top_k: Maximum number of documents to return.
    :return: Pipeline
    """

    pipe, retrievers, stores = build_document_pipeline(db=db, generator_config=generator_config, top_k=top_k)

    prompt_tmpl = """
You are an experienced web‑application penetration tester. Below are crawl/scan artefacts from a single website. Identify high‑impact vulnerabilities and exploitation paths.

{% for doc in documents %}
URL: {{ doc.meta.url }}
Collection: {{ doc.meta.collection }}
{{ doc.content }}
{% endfor %}

Question: {{ query }}
Answer in concise Markdown with PoCs/examples. Include the URL for documents that contributed to the answer.
"""

    generator = generator_config.create_generator()
    pipe.add_component("prompt", PromptBuilder(template=prompt_tmpl, required_variables=["documents", "query"]))
    pipe.add_component("llm", generator)
    pipe.add_component("ans", AnswerBuilder())

    pipe.connect("combine", "prompt.documents")
    pipe.connect("query", "prompt.query")
    pipe.connect("query", "ans.query")
    pipe.connect("prompt", "llm.prompt")
    pipe.connect("llm", "ans.replies")

    return pipe, generator


def _create_shyhurriance_toolset() -> MCPToolset:
    return MCPToolset(
        server_info=StreamableHttpServerInfo(url="http://127.0.0.1:8000/mcp/"),
        invocation_timeout=120.0
    )


pentester_system_prompt = """
You are an experienced penetration tester assistant.
Your task is to find and exploit vulnerabilities in networks, computers and websites. Use the available tools to gather more information to accomplish your task.

You must stay in the target scope given by the user. If given a URL or host name, do not perform tasks outside the host name, including subdomains. You may report if a subdomain is found. If given an IP address, do not look beyond that IP address. You may examine host names mapped to that IP address. If given a subnet, do not look for hosts beyond that subnet. The user is allowed to instruct you to increase the scope by giving more IP addresses, host names or subnets.

For websites, you start looking for vulnerabilities from the OWASP Top 10. Follow common penetration testing methodologies.

Use available tools to enumerate the targets to gather more information to accomplish your task.

Provide explanations for found vulnerabilities and exploit paths. Provide concise Markdown. Include URLs for cross-reference as appropriate. Answer with the same language as the user. 
"""


def build_chat_pipeline(generator_config: GeneratorConfig) -> Tuple[Pipeline, Component, Toolset]:
    """
    Builds a pipeline for a cyber-security chat.
    :return: Pipeline, generator component
    """

    tools = _create_shyhurriance_toolset()
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={
            # "temperature": 0.9,
        }
    )
    response_chat_generator = generator_config.create_chat_generator(
        generation_kwargs={
            # "temperature": 0.9,
        }
    )

    pipeline = Pipeline()
    pipeline.add_component("llm", chat_generator)
    pipeline.add_component("tool_invoker", ToolInvoker(tools=tools))
    pipeline.add_component("list_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("response_llm", response_chat_generator)
    pipeline.connect("llm.replies", "tool_invoker.messages")
    pipeline.connect("llm.replies", "list_joiner")
    pipeline.connect("tool_invoker.tool_messages", "list_joiner")
    pipeline.connect("list_joiner.values", "response_llm.messages")

    return pipeline, response_chat_generator, tools


def build_agent_pipeline(generator_config: GeneratorConfig) -> Tuple[Pipeline, Component, Toolset]:
    """
    Builds a pipeline for a cyber-security agent.
    :return: Pipeline
    """

    tools = _create_shyhurriance_toolset()
    prompt_builder = ChatPromptBuilder()
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={
            # "num_predict": 100,  # Ollama only?
            # "temperature": 0.9,
        }
    )
    assistant = Agent(
        chat_generator=chat_generator,
        tools=tools,
        system_prompt=pentester_system_prompt,
        exit_conditions=["text"],
        max_agent_steps=100,
        raise_on_tool_invocation_failure=False
    )
    pipe = Pipeline()
    pipe.add_component("prompt_builder", prompt_builder)
    pipe.add_component("agent", assistant)
    pipe.connect("prompt_builder", "agent")
    return pipe, chat_generator, tools


def build_document_pipeline(db: str, generator_config: GeneratorConfig, top_k: int) -> Tuple[
    Pipeline, Dict[str, MultiQueryChromaRetriever], Dict[str, ChromaDocumentStore]]:
    """
    Builds a pipeline for retrieving documents from the store.
    :param db: path to the database.
    :param top_k: Maximum number of documents to return.
    :return: Pipeline
    """
    collections = list_collections(db)

    pipe = Pipeline()
    comb = CombineDocs([f"{col}_documents" for col in collections])
    pipe.add_component("combine", comb)
    pipe.add_component("query", Query())
    pipe.add_component("query_expander", QueryExpander(generator_config))
    pipe.connect("query.text", "query_expander.query")

    retrievers: Dict[str, MultiQueryChromaRetriever] = {}
    stores: Dict[str, ChromaDocumentStore] = {}

    for col in collections:
        # Components per collection
        model_name = get_model_for_doc_type(col)
        ret_name = f"ret_{col}"

        embedder = SentenceTransformersTextEmbedder(model=model_name, progress_bar=False)
        store = ChromaDocumentStore(persist_path=db, collection_name=col)
        retriever = ChromaEmbeddingRetriever(document_store=store, top_k=top_k)
        multiquery_retriever = MultiQueryChromaRetriever(embedder, retriever, top_k=top_k)

        pipe.add_component(ret_name, multiquery_retriever)

        # wiring: Query → embedder → retriever → combiner
        pipe.connect("query_expander.queries", ret_name + ".queries")
        pipe.connect("query.filters", ret_name + ".filters")
        pipe.connect(ret_name + ".documents", f"combine.{col}_documents")

        retrievers[col] = multiquery_retriever
        stores[col] = store

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
      Output the two pieces of information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      
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


@component
class KatanaDocument:
    def __init__(self, embedders: Dict[str, Any], doc_cleaner: DocumentCleaner):
        self.embedders = embedders
        self.doc_cleaner = doc_cleaner

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
        response_body = entry.get("response", {}).get("body", None)
        content = "\n".join(
            list(filter(lambda x: x is not None, [
                entry.get("request", {}).get("body", None),
                response_body,
            ]))
        )
        status_code = entry["response"].get("status_code", 0)
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

        base_meta = {
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

        documents = []

        # Map MIME to a logical doc type
        doc_type = map_mime_to_type(raw_mime)

        # ─ Content Document (if body is present)
        if response_body and not is_binary(response_body, raw_mime):
            doc = Document(
                content=response_body,
                meta=base_meta | {"type": "content"},
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
            meta=base_meta | {"type": "network"},
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
                meta=base_meta | {"type": "forms"},
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

    def run(self, documents: List[Document]):
        for doc in documents:
            self.stores.get(doc.meta.get('type')).write_documents([doc])
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


def build_ingest_pipeline(db: str) -> Pipeline:
    os.makedirs(db, exist_ok=True)

    stores = {}
    embedders = {}
    for dtype, model_name in doc_type_to_model.items():
        embedder = SentenceTransformersDocumentEmbedder(
            model=model_name,
            progress_bar=False)
        embedder.warm_up()
        document_store = ChromaDocumentStore(
            persist_path=db,
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

    pipe.connect("input_router.katana_jsonl", "katana_document.text")
    pipe.connect("input_router.http_raw_text", "raw_document.text")
    pipe.connect("input_router.har_json", "har_document.text")

    pipe.connect("katana_document", "katana_store")
    pipe.connect("raw_document", "raw_store")
    pipe.connect("har_document", "har_store")

    return pipe
