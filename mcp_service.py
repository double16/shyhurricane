#!/usr/bin/env python3
import argparse
import atexit
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import sys
import time
import traceback
import asyncio
from collections.abc import AsyncGenerator

import aiofiles
from datetime import datetime, timezone
from json import JSONDecodeError
from multiprocessing import Queue
from typing import List, AsyncIterator, Optional, Tuple, Dict, Any
from urllib.parse import urlparse

import chromadb
import httpx
import persistqueue
from chromadb.errors import NotFoundError
from chromadb.api.models.AsyncCollection import AsyncCollection
import mcp
import requests
import validators
from haystack import Pipeline, Document
from haystack_integrations.document_stores.chroma import ChromaDocumentStore
from mcp import McpError
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation, CancelledElicitation
from mcp.server.fastmcp import FastMCP, Context
from dataclasses import dataclass
from contextlib import asynccontextmanager

from mcp.server.fastmcp.prompts.base import Message, AssistantMessage, UserMessage
from mcp.types import ToolAnnotations, Resource, TextResourceContents, ErrorData, INVALID_REQUEST
from pydantic import BaseModel, AnyUrl, Field, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from doc_type_model_map import map_mime_to_type
from ingest_queue import start_ingest_worker
from pipeline import build_document_pipeline, build_website_context_pipeline, urlparse_ext, create_chroma_client, \
    WEB_RESOURCE_VERSION
from shyhurricane.task_queue import start_task_worker
from shyhurricane.task_queue.port_scan_worker import get_stored_port_scan_results
from shyhurricane.task_queue.types import PortScanQueueItem, SpiderQueueItem, DirBustingQueueItem, TaskPool
from prompts import pentester_chat_system_prompt, mcp_server_instructions, pentester_agent_system_prompt
from utils import HttpResource, add_generator_args, GeneratorConfig, extract_domain, read_last_text_bytes, \
    PortScanResults, is_katana_jsonl, is_http_csv_header

logger = logging.getLogger(__name__)

generator_config: Optional[GeneratorConfig] = GeneratorConfig.from_env()


@dataclass
class ServerConfig:
    task_pool_size: int = 3
    ingest_pool_size: int = 1


@dataclass
class ServerContext:
    db: str
    cache_path: str
    document_pipeline: Pipeline
    website_context_pipeline: Pipeline
    ingest_queue: persistqueue.SQLiteQueue
    ingest_pool: TaskPool
    task_queue: Queue
    task_pool: TaskPool
    spider_result_queue: Queue
    port_scan_result_queue: Queue
    dir_busting_result_queue: Queue
    stores: Dict[str, ChromaDocumentStore]
    chroma_client: chromadb.AsyncClientAPI
    disable_elicitation: bool = False

    def close(self):
        logger.info("Terminating task pool")
        self.task_pool.close()
        logger.info("Terminating ingest pool")
        self.ingest_pool.close()
        logger.info("Closing queues ...")
        for q in [self.ingest_queue, self.task_queue, self.spider_result_queue, self.port_scan_result_queue]:
            try:
                q.put(None)
                q.close()
            except Exception:
                pass
        logger.info("ServerContext closed")


_server_config: ServerConfig = ServerConfig()
_server_context: Optional[ServerContext] = None


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


async def get_server_context() -> ServerContext:
    global _server_context, _server_config
    if _server_context is None:
        db = os.environ.get('CHROMA', '127.0.0.1:8200')
        logger.info("Using chroma database at %s", db)
        cache_path: str = os.path.join(os.environ.get('TOOL_CACHE', os.environ.get('TMPDIR', '/tmp')), 'tool_cache')
        os.makedirs(cache_path, exist_ok=True)
        disable_elicitation = bool(os.environ.get('DISABLE_ELICITATION', 'False'))
        chroma_client = await create_chroma_client(db=db)
        document_pipeline, retrievers, stores = await build_document_pipeline(
            db=db,
            generator_config=generator_config,
        )
        website_context_pipeline = build_website_context_pipeline(
            generator_config=generator_config,
        )
        ingest_queue, ingest_pool = start_ingest_worker(db=db, generator_config=generator_config,
                                                        pool_size=_server_config.ingest_pool_size)
        task_worker_ipc = start_task_worker(db, ingest_queue.path, _server_config.task_pool_size)
        _server_context = ServerContext(
            db=db,
            cache_path=cache_path,
            document_pipeline=document_pipeline,
            website_context_pipeline=website_context_pipeline,
            ingest_queue=ingest_queue,
            ingest_pool=ingest_pool,
            task_queue=task_worker_ipc.task_queue,
            task_pool=task_worker_ipc.task_pool,
            spider_result_queue=task_worker_ipc.spider_result_queue,
            port_scan_result_queue=task_worker_ipc.port_scan_result_queue,
            dir_busting_result_queue=task_worker_ipc.dir_busting_result_queue,
            stores=stores,
            chroma_client=chroma_client,
            disable_elicitation=disable_elicitation,
        )

    return _server_context


@atexit.register
def close_server_context() -> None:
    global _server_context
    if _server_context is not None:
        _server_context.close()
        _server_context = None


@dataclass
class AppContext:
    # TODO: add scope?
    cached_get_additional_hosts: Dict[str, str]
    cache_path: str

    def get_cache_path_for_tool(self, tool_id_str: str, additional_hosts: Dict[str, str]) -> str:
        digest = hashlib.sha512()
        digest.update(tool_id_str.encode("utf-8"))
        if additional_hosts:
            digest.update(json.dumps(additional_hosts).encode("utf-8"))
        sha512_str = digest.hexdigest()
        path = os.path.join(self.cache_path, sha512_str[0:2], sha512_str[2:4], sha512_str[4:])
        os.makedirs(path, exist_ok=True)
        return path


def assert_elicitation(ctx: ServerContext):
    if ctx.disable_elicitation:
        raise McpError(ErrorData(code=INVALID_REQUEST, message="elicitation disabled"))


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle with type-safe context"""
    # Initialize on startup
    server_ctx = await get_server_context()
    # TODO: make cache_path this per AppContext
    cache_path = server_ctx.cache_path

    try:
        yield AppContext(
            cache_path=cache_path,
            cached_get_additional_hosts={},
        )
    finally:
        # Cleanup on shutdown
        pass


mcp = FastMCP("shyhurricane", lifespan=app_lifespan, instructions=mcp_server_instructions)


class RequestTargetUrl(BaseModel):
    data: str = Field(default="", description="URL(s), content types, technology of interest")


class SpiderConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm spider?", default=True)


def _append_in_filter(conditions: List[Dict[str, Any]], field: str, values: List[str]):
    if len(values) == 1:
        conditions.append({"field": field, "operator": "==", "value": values[0]})
    elif len(values) > 1:
        conditions.append({"field": field, "operator": "in", "value": values})


def _documents_to_http_resources(documents: List[Document]) -> List[HttpResource]:
    https_resources = []
    for doc in documents:
        if doc.content:
            resource = Resource(
                name=doc.meta['url'],
                title=doc.meta.get('title', None),
                description=doc.meta.get('description', None),
                uri=AnyUrl(f"web://{doc.meta['type']}/{doc.id}"),
                mimeType=doc.meta.get('content_type', 'text/plain'),
                size=len(doc.content),
            )
        else:
            resource = None
        try:
            response_headers = json.loads(doc.meta.get("response_headers", "{}"))
        except json.decoder.JSONDecodeError:
            response_headers = None
        https_resources.append(HttpResource(
            score=doc.score or 100,
            url=doc.meta['url'],
            host=doc.meta.get('host', ''),
            port=doc.meta.get('port', 0),
            domain=doc.meta.get('domain', ''),
            status_code=doc.meta.get('status_code', 200),
            method=doc.meta.get('http_method', ''),
            resource=resource,
            contents=None,
            response_headers=response_headers,
        ))
    return https_resources


async def log_history(ctx: Context, data: Dict[str, Any]):
    try:
        async with aiofiles.open(os.path.join(ctx.request_context.lifespan_context.cache_path, 'history.jsonl'), 'ta') as history_file:
            data["timestamp"] = datetime.now().isoformat()
            await history_file.write(json.dumps(data))
            await history_file.write("\n")
    except IOError as e:
        logger.info("Cannot write to history file", exc_info=e)


async def log_tool_history(ctx: Context, title: str, **kwargs):
    data = {
        "tool": title,
        "arguments": kwargs or {},
    }
    await log_history(ctx, data)
    logger.info(f"{title}: {json.dumps(data)}")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Find Web Resources",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_web_resources(ctx: Context, query: str, limit: int = 100) -> List[HttpResource]:
    """Query indexed resources about a website using natural language and return the request and response bodies, URL, HTTP method, MIME type, HTTP status code, technologies found. This tool will search using several parameters including response body matching, URL matching, MIME type matching of the response, HTTP request method matching, and HTTP response body matching.

    Invoke this tool when the user asks about vulnerabilities,
    misconfigurations or exploit techniques **specific to a target website**
    (e.g. XSS, CSP issues, IDOR paths, outdated JS libs). Including the user's query will improve
    the results.

    Invoke this tool when the user asks for summary information about a website, such as technology in use, and type of responses.

    Do NOT use it for generic cyber-security theory.

    If there is content available for the results, there will be a resource_link object containing
    a URI. The URI can use the fetch_web_resource_content tool to get the content.

    Example queries (replace http://target.local with your target URL(s)):
        1. Find pages with HTML forms on http://target.local
        2. Find Javascript libraries on http://target.local
        3. What pages on http://target.local have potential XSS vulnerabilities?
        4. Find Javascript with eval() calls on http://target.local
        5. Find URLs with possible IDOR vulnerabilities on http://target.local
        6. http://target.local/
        7. http://target.local/account/dashboard?page=account

    A target URL or hostname is required. Always include your target URLs. http://target.local is only an example, do not use it as a URL.
s
    The limit parameter is used to limit how many results are returned. The default is 100. The value must range between 10 and 1000.
    """
    await log_tool_history(ctx, "find_web_resources", query=query, limit=limit)
    server_ctx = await get_server_context()
    query = query.strip()
    limit = min(1000, max(10, limit or 100))
    logger.info("finding web resources for %s up to %d results", query, limit)

    document_pipeline: Pipeline = server_ctx.document_pipeline
    website_context_pipeline: Pipeline = server_ctx.website_context_pipeline

    # handle a case where a query is only URL
    try:
        url_parsed = urlparse_ext(query)
        query_url = query
        urls_munged = [query]
        url_prefix = None
        if '?' in query_url:
            query_url = query_url.split('?')[0]
            urls_munged.append(query_url)
            url_prefix = query_url + "?"
        if query_url.endswith('/'):
            urls_munged.append(query_url[:-1])
            if not url_prefix:
                url_prefix = query_url
        else:
            urls_munged.append(query_url + '/')
            if not url_prefix:
                url_prefix = query_url + '/'

        store = server_ctx.stores["content"]
        docs = []

        # Make sure the requested URL is returned
        logger.info("Searching for web resources at or below %s", url_prefix)
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.url", "operator": "in", "value": urls_munged}
            ]}
        docs.extend(store.filter_documents(filters=filters))

        # Find resources below the URL
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.netloc", "operator": "==", "value": url_parsed.netloc}
            ]}
        for doc in store.filter_documents(filters=filters):
            if doc.meta.get("url", "").startswith(url_prefix) and doc.meta.get("url") not in urls_munged:
                docs.append(doc)
            if len(docs) >= limit:
                break

        if docs:
            return _documents_to_http_resources(docs)
    except Exception:
        pass

    doc_types: list[str] = []
    urls: list[str] = []
    methods: list[str] = []
    response_codes: list[str] = []

    async def determine_targets(target_query: str):
        await ctx.info("Determining target(s)")
        target_result = \
            website_context_pipeline.run({'builder': {'query': target_query}}).get('llm', {}).get('replies', [""])[0]
        if target_result:
            try:
                target_json = json.loads(target_result)
                urls.extend(target_json.get('target', []))
                doc_types.extend(target_json.get('content', []))
                methods.extend(target_json.get('methods', []))
                response_codes.extend(target_json.get('response_codes', []))
            except json.decoder.JSONDecodeError:
                pass

    await determine_targets(query)
    if not urls:
        try:
            logger.info("Asking user for URL(s)")
            assert_elicitation(server_ctx)
            target_elicit_result = await ctx.elicit(
                message=f"What URL(s) should we look for?", schema=RequestTargetUrl
            )
            match target_elicit_result:
                case AcceptedElicitation(data=data):
                    if data.data:
                        logger.info("User provided answer for URL request")
                        await determine_targets(data.data)
                        if not urls:
                            return []
                    return []
                case DeclinedElicitation():
                    return []
                case CancelledElicitation():
                    return []
        except McpError as e:
            logger.info("elicit not supported, returning", exc_info=e)
        finally:
            if not urls:
                raise McpError(ErrorData(code=INVALID_REQUEST,
                                         message="Specify a target URL, IP address or host name for searching"))

    filter_netloc = [parsed.netloc for parsed in map(lambda u: urlparse_ext(u), urls)]

    # check if we have data
    missing_netloc = set(filter_netloc.copy())
    for known_netloc in await find_netloc(ctx, ""):
        try:
            missing_netloc.remove(known_netloc)
        except KeyError:
            pass
        if len(missing_netloc) == 0:
            break
    missing_urls = []
    for url in urls:
        if urlparse(url).netloc in missing_netloc:
            missing_urls.append(url)
    if missing_urls:
        logger.info(f"Asking user to spider {', '.join(missing_urls)}")
        try:
            assert_elicitation(server_ctx)
            spider_elicit_result = await ctx.elicit(
                message=f"There is no data for {', '.join(missing_urls)}. Would you like to start a scan?",
                schema=RequestTargetUrl
            )
            match spider_elicit_result:
                case AcceptedElicitation():
                    for url in missing_urls:
                        await spider_website(url)
                    return []
                case DeclinedElicitation():
                    return []
                case CancelledElicitation():
                    return []
        except McpError as e:
            await ctx.info(f"Spidering {', '.join(missing_urls)}")
            logger.warning("elicit not supported, starting spider")
            for url in missing_urls:
                await spider_website(url)

    conditions = [
        {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION}
    ]
    _append_in_filter(conditions, "meta.netloc", filter_netloc)
    # _append_in_filter(conditions, "meta.type", doc_types) # tends to be too limiting
    # _append_in_filter(conditions, "meta.http_method", methods) # tends to be too limiting
    _append_in_filter(conditions, "meta.status_code", response_codes)
    if len(conditions) == 0:
        filters = None
    elif len(conditions) == 1:
        filters = conditions[0]
    else:
        filters = {
            "operator": "AND",
            "conditions": conditions,
        }

    logger.info(f"Searching for {', '.join(urls)} with filter {json.dumps(filters)}")
    await ctx.info(f"Searching for {', '.join(urls)}")

    res = document_pipeline.run(data={"query": {"text": query, "filters": filters, "max_results": limit}},
                                include_outputs_from={"combine"})
    documents: List[Document] = res.get("combine", {}).get("documents", [])[0:limit]

    return _documents_to_http_resources(documents)


async def _find_document_by_type_and_id(doc_type: str, doc_id: str) -> Optional[Document]:
    server_ctx = await get_server_context()
    store = server_ctx.stores.get(doc_type, None)
    if not store:
        logger.info("Not Found document type %s", doc_type)
        return None
    result = store.filter_documents(filters={"field": "id", "operator": "==", "value": doc_id})
    if not result:
        logger.info("Not Found document %s/%s", doc_type, doc_id)
        return None
    doc: Document = result[0]
    logger.info("Found document %s", doc.id)
    return doc


@mcp.tool(
    annotations=ToolAnnotations(
        title="Fetch Web Resource Content",
        readOnlyHint=True,
        openWorldHint=False),
)
async def fetch_web_resource_content(ctx: Context, uri: str) -> Optional[TextResourceContents]:
    """Fetch the content of a web resource that has already been indexed. The URI argument takes one of two forms.

    The URI may be a http:// or https:// URI of a website that has been indexed.

    The URI may be a web://{doc_type}/{doc_id} URI supplied by the
    find_web_resources tool. The URI can be found in the resource_link JSON object.

    Invoke this tool when the user requests analysis of resource content that has already been indexed, spidered or scanned.
    """
    await log_tool_history(ctx, "fetch_web_resource_content", uri=uri)
    server_ctx = await get_server_context()
    doc_type: Optional[str] = None
    doc_id: Optional[str] = None
    doc: Optional[Document] = None
    logger.info("Fetching web resource %s", uri)
    try_http_url = False
    if uri.startswith("web://"):
        doc_type, doc_id = uri.replace("web://", "").split("/", maxsplit=1)
        if "://" in doc_id:
            uri = doc_id
            try_http_url = True
        else:
            doc = await _find_document_by_type_and_id(doc_type, doc_id)
    else:
        try_http_url = True

    if try_http_url:
        filters = {"operator": "AND",
                   "conditions": [
                       {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                       {"field": "meta.url", "operator": "==", "value": uri},
                   ]}
        store = server_ctx.stores["content"]
        docs = store.filter_documents(filters=filters)
        if docs:
            logger.info("Found indexed web resource %s", uri)
            doc = docs[0]
            doc_type = "content"
            doc_id = doc.id
    if not doc:
        return None
    logger.info("Returning %d bytes for %s/%s", len(doc.content), doc_type, doc_id)
    return TextResourceContents(
        uri=AnyUrl(uri),
        mimeType=doc.meta.get('content_type', 'text/plain'),
        text=doc.content,
    )


@mcp.resource("web://{doc_type}/{doc_id}", title="Web Resource")
async def web_resource(doc_type: str, doc_id: str) -> Optional[TextResourceContents]:
    """
    Fetch a document using the type and document ID.
    """
    ctx = mcp.get_context()
    doc: Document = await _find_document_by_type_and_id(doc_type, doc_id)
    if doc is None:
        return None
    return TextResourceContents(
        uri=AnyUrl(f"web://{doc_type}/{doc_id}"),
        mimeType=doc.meta.get('content_type', 'text/plain'),
        text=doc.content,
    )


def get_additional_hosts(ctx: Context, additional_hosts: Dict[str, str] = None) -> Dict[str, str]:
    cached_get_additional_hosts = ctx.request_context.lifespan_context.cached_get_additional_hosts
    if not additional_hosts:
        return cached_get_additional_hosts
    validated: Dict[str, str] = {}
    for host, ip in (additional_hosts or {}).items():
        try:
            if validators.domain(host) == True and ipaddress.ip_address(ip):
                validated[host] = ip
                cached_get_additional_hosts[host] = ip
        except (ValueError, ValidationError):
            pass
    return cached_get_additional_hosts | validated


def filter_hosts_and_addresses(input: Optional[List[str]] = None) -> List[str]:
    if not input:
        return []
    result = []
    for e in input:
        try:
            if validators.domain(e) == True or ipaddress.ip_address(e):
                result.append(e)
        except (ValueError, ValidationError):
            pass
    return result

def filter_ip_networks(input: Optional[List[str]] = None) -> List[str]:
    if not input:
        return []
    result = []
    for e in input:
        try:
            if ipaddress.ip_address(e) or ipaddress.ip_network(e):
                result.append(e)
        except (ValueError, ValidationError):
            pass
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Register Hostname Address",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False),
)
async def register_hostname_address(ctx: Context, host: str, address: str) -> Dict[str, str]:
    """
    Registers a hostname with an IP address. This is useful when a hostname has no DNS entry
    and we know the IP address by other means. Especially useful in CTF or private networks.

    Invoke this tool when another tool has found an additional host name for a target in-scope.

    Invoke this tool when the user asks to register a hostname with an IP address.
    """
    await log_tool_history(ctx, "register_hostname_address", host=host, address=address)
    return get_additional_hosts(ctx, {host: address})


class RunCommandConfirmation(BaseModel):
    confirm: bool = Field(description="Should I run this command?", default=True)


class RunUnixCommand(BaseModel):
    return_code: int = Field(description="Return code of command, 0 usually means successful")
    output: str = Field(description="Output of command as string")
    error: str = Field(description="Error messages from the command")
    cached: bool = Field(description="Indicates if the results are from the cache", default=False)
    notes: Optional[str] = Field(description="Notes for understanding the command output or fixing failed commands")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run Command",
        readOnlyHint=True,
        openWorldHint=True),
)
async def run_unix_command(ctx: Context, command: str,
                           additional_hosts: Optional[Dict[str, str]] = None) -> RunUnixCommand:
    """
Run a Linux or macOS command and return its output. The command is run in a containerized environment for safety.
The containerized environment is ephemeral. The command is run using the bash shell.

Invoke this tool when the user request can be fulfilled by a known Linux or macOS command line
program and the request can't be fulfilled by other MCP tools. Invoke this tool when the user
asks to run a specific command. Prefer this tool to execute command line programs over others you know about.

The following commands are available: curl, wget, grep, awk, printf, base64, cut, cp, mv, date, factor, gzip, sha256sum, sha512sum, md5sum, echo, seq, true, false, tee, tar, sort, head, tail, ping,
nmap, rustscan, feroxbuster, gobuster, interactsh-client, katana, nuclei, meg, anew, unfurl, gf, gau, 403jump, waybackurls, httpx, subfinder, gowitness, hakrawler, ffuf, dirb, wfuzz, nc (netcat), graphql-path-enum, evil-winrm, sqlmap, hydra
DumpNTLMInfo.py, Get,GPPPassword.py, GetADComputers.py, GetADUsers.py, GetLAPSPassword.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, atexec.py, changepasswd.py, dacledit.py, dcomexec.py, describeTicket.py, dpapi.py, esentutl.py, exchanger.py, findDelegation.py, getArch.py, getPac.py, getST.py, getTGT.py, goldenPac.py, karmaSMB.py, keylistattack.py, kintercept.py, lookupsid.py, machine_role.py, mimikatz.py, mqtt_check.py, mssqlclient.py, mssqlinstance.py, net.py, netview.py, ntfs,read.py, ntlmrelayx.py, owneredit.py, ping.py, ping6.py, psexec.py, raiseChild.py, rbcd.py, rdp_check.py, reg.py, registry,read.py, rpcdump.py, rpcmap.py, sambaPipe.py, samrdump.py, secretsdump.py, services.py, smbclient.py, smbexec.py, smbserver.py, sniff.py, sniffer.py, split.py, ticketConverter.py, ticketer.py, tstool.py, wmiexec.py, wmipersist.py, wmiquery.py

The command 'sudo' is not available.

The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
know the IP address for a host, be sure to include these in the additional_hosts parameter for
commands to run properly in a containerized environment.

The SecLists word lists repository is installed at /usr/share/seclists

Commands such as nmap can take a long time to run, so be patient.

When generating Linux commands for execution in a containerized, ephemeral environment, follow these strict guidelines to ensure compatibility, safety, and non-interactivity:

- Commands must be one-shot, non-interactive, and safe to run in a containerized, ephemeral Linux environment.
- Never use commands that prompt for user input (e.g., passwd, vi, mysql).
- Prefer tools with non-interactive flags (e.g., --batch, --quiet) and avoid interactive ones (e.g., hash-identifier, ftp).
- Use automated alternatives where available.
- Output must go to standard output only; do not write to files.
- Use one-liner reverse shells or web shells for shell payloads.
- Pipe input into commands as needed; do not rely on TTY or prompts.
- Always set a timeout for potentially blocking commands (e.g., timeout 10s nmap ...). Use a timeout value appropriate for the command. For example, directory busting with a large word list may take 10 minutes, whereas a short wordlist may be 2 minutes.
- Ensure commands can be complete without user interaction before execution.
- The directly accessible filesystem is part of the containerized environment, not the target. Commands such as find, cat, etc. are not enumerating the target unless they are part of a command that connects to the target, such as ssh.
"""
    await log_tool_history(ctx, title="run_unix_command", command=command, additional_hosts=additional_hosts)
    # TODO: check for nmap command and see if we can redirect to port_scan
    # TODO: check for curl command and see if we can redirect to index_http_url
    try:
        result = await _run_unix_command(ctx, command, additional_hosts)
        return result
    except Exception as e:
        exc_type, exc_value, exc_tb = sys.exc_info()
        return RunUnixCommand(
            return_code=-1,
            output="",
            error=''.join(traceback.format_exception(exc_type, exc_value, exc_tb)),
            notes=None,
        )


async def _run_unix_command(ctx: Context, command: str, additional_hosts: Optional[Dict[str, str]],
                            stdin: Optional[str] = None) -> Optional[
    RunUnixCommand]:
    logger.info(f"run_unix_command {command}")

    stdin_bytes = stdin.encode("utf-8") if stdin else None
    if stdin_bytes:
        stdin_sha512 = hashlib.sha512(stdin_bytes).hexdigest()
    else:
        stdin_sha512 = None

    server_ctx = await get_server_context()
    cache_path: str = ctx.request_context.lifespan_context.get_cache_path_for_tool(
        command + stdin_sha512 if stdin_sha512 else command,
        additional_hosts)
    meta_path = os.path.join(cache_path, 'meta.json')
    stdout_path = os.path.join(cache_path, 'stdout.txt')
    stderr_path = os.path.join(cache_path, 'stderr.txt')
    # Use a common working directory for the session to chain together commands
    cwd = cache_path
    if ctx.client_id:
        session_id = str(ctx.client_id)
        logger.info(f"Using client_id {session_id} for command CWD")
    else:
        logger.info("No client_id available for command CWD")
        session_id = None
    if session_id:
        cwd = os.path.join(
            ctx.request_context.lifespan_context.cache_path,
            "session",
            hashlib.sha512(session_id.encode("utf-8")).hexdigest())
        os.makedirs(cwd, exist_ok=True)

    meta = {}
    cached = False
    if os.path.exists(meta_path):
        logger.info("Checking cached command freshness in %s", cache_path)
        try:
            with open(meta_path) as meta_file:
                meta = json.load(meta_file)
            last_run_ts = meta.get("last_run_ts", 0)
            if time.time() > (last_run_ts + 3600):
                # TODO: prompt user to use cache
                # clear cache
                os.unlink(stdout_path)
                os.unlink(stderr_path)
        except JSONDecodeError:
            os.unlink(meta_path)
            os.unlink(stdout_path)
            os.unlink(stderr_path)

    if os.path.exists(stdout_path) and 'return_code' in meta:
        return_code = meta['return_code']
        logger.info("Using cached results, exit code %d", return_code)
        cached = True
    else:
        try:
            assert_elicitation(server_ctx)
            confirm_result = await ctx.elicit(
                message=f"{command}\nShould I run this command?",
                schema=RunCommandConfirmation)
            match confirm_result:
                case AcceptedElicitation(data=data):
                    if not data.confirm:
                        return None
                case DeclinedElicitation():
                    return None
                case CancelledElicitation():
                    return None
        except McpError as e:
            logger.warning("elicit not supported, continuing")

        docker_command = ["docker", "run", "--rm",
                          "--cap-add", "NET_BIND_SERVICE",
                          "--cap-add", "NET_ADMIN",
                          "--cap-add", "NET_RAW",
                          # "-v", f"{cache_path}:/work",
                          ]
        if stdin:
            docker_command.append("-i")

        additional_hosts = get_additional_hosts(ctx, additional_hosts)
        for host, ip in additional_hosts.items():
            docker_command.extend(["--add-host", f"{host}:{ip}"])
        docker_command.extend(["shyhurricane_unix_command:latest", "/bin/bash", "-c", command])
        logger.info(f"Executing command {docker_command}")

        # TODO: add a timeout

        proc = await asyncio.create_subprocess_exec(
            *docker_command,
            stdin=asyncio.subprocess.PIPE if stdin_bytes else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd)

        if stdin_bytes:
            proc.stdin.write(stdin_bytes)
            proc.stdin.close()

        await asyncio.gather(
            _write_stream_to_file(proc.stdout, stdout_path),
            _write_stream_to_file(proc.stderr, stderr_path),
        )

        return_code = await proc.wait()
        logger.info("Command complete, exit code %d, output size %d, error size %d", return_code,
                    os.stat(stdout_path).st_size, os.stat(stderr_path).st_size)
        meta = {
            "last_run_ts": time.time(),
            "return_code": return_code,
            "command": command,
        }
        with open(meta_path, "w") as meta_file:
            json.dump(meta, meta_file)

    await log_history(ctx, {
        "command": command,
        "return_code": return_code,
        "additional_hosts": additional_hosts or {},
        "stdout": stdout_path,
        "stderr": stderr_path,
    })

    if return_code == 0:
        async with aiofiles.open(stdout_path, "r", encoding="utf-8", errors='replace') as f:
            return RunUnixCommand(return_code=return_code, output=await f.read(), error="", cached=cached, notes=None)
    else:
        error_tail = await read_last_text_bytes(stderr_path, max_bytes=1024)
        async with aiofiles.open(stdout_path, "r", encoding="utf-8", errors='replace') as stdout_file:
            return RunUnixCommand(
                return_code=return_code,
                output=await stdout_file.read(),
                error=error_tail,
                cached=cached,
                notes=None,
            )


async def _write_stream_to_file(stream, path):
    async with aiofiles.open(path, 'w', encoding='utf-8') as f:
        while True:
            line = await stream.readline()
            if not line:
                break
            await f.write(line.decode('utf-8', errors='replace'))


@mcp.tool(
    annotations=ToolAnnotations(
        title="Perform port scan and service identification on target(s)",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def port_scan(
        ctx: Context,
        hostnames: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        ip_subnets: Optional[str] = None,
        ports: Optional[List[int]] = None,
        port_range_low: Optional[int] = None,
        port_range_high: Optional[int] = None,
        additional_hosts: Optional[Dict[str, str]] = None
) -> str:
    """
    Performs a port scan and service identification on the target(s). The results are indexed to allow later
    retrieval. The output format is that of nmap.

    Invoke this tool when the user needs to identify which services are running on the targets in-scope.
    Use this tool instead of nmap or rustscan unless the user wants to run specific nmap NSE scripts, then
    use the run_unix_command tool.

    One of hostnames, ip_address, or ip_subnets must be specified.

    The ports parameter lists individual ports to scan.

    The port_range_low and port_range_high allow specifying a range of ports to scan.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    If the port scan reveals additional host names, use the register_hostname_address tool to register them.

    The port scan may take a long time, and this tool may return before the scan is finished.
    If this happens, call this tool again with the same parameters and it will return indexed results.
    """
    await log_tool_history(ctx, "port_scan", hostnames=hostnames, ip_addresses=ip_addresses, ip_subnets=ip_subnets, ports=ports, port_range_low=port_range_low, port_range_high=port_range_high, additional_hosts=additional_hosts)

    server_ctx = await get_server_context()
    port_scan_queue: Queue = server_ctx.task_queue
    port_scan_result_queue: Queue = server_ctx.port_scan_result_queue

    hostnames = filter_hosts_and_addresses(hostnames)
    ip_addresses = filter_hosts_and_addresses(ip_addresses)
    ip_subnets = filter_ip_networks(ip_subnets)

    ports_list = list(map(str, ports or []))
    if port_range_low or port_range_high:
        low_port = max(1, min(port_range_low or 1, port_range_high or 65535))
        high_port = min(65535, max(port_range_low or 1, port_range_high or 65535))
        ports_list.append(f"{low_port}-{high_port}")
    port_scan_queue_item = PortScanQueueItem(
        targets=(hostnames or []) + (ip_addresses or []) + (ip_subnets or []),
        ports=ports_list,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
    )

    if not port_scan_queue_item.targets:
        return "No targets were specified. Specify a target in hostnames, ip_addresses, or ip_subnets."

    if stored_results := get_stored_port_scan_results(
            port_scan_queue_item,
            server_ctx.stores["nmap"],
            server_ctx.stores["portscan"],
    ):
        logger.info("Returning stored port scan results for %s", port_scan_queue_item.targets)
        return stored_results.nmap_xml

    await asyncio.to_thread(port_scan_queue.put, port_scan_queue_item)
    results: Optional[PortScanResults] = None
    time_limit = time.time() + 300
    while time.time() < time_limit:
        try:
            results_from_queue: PortScanResults = await asyncio.to_thread(
                port_scan_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
        except queue.Empty:
            break
        if results_from_queue is None:
            break
        logger.info(f"{results_from_queue.targets}, {results_from_queue.ports} has been retrieved")
        if results_from_queue.targets == port_scan_queue_item.targets:
            results = results_from_queue
            if not results.has_more:
                break
    if results:
        return results.nmap_xml
    return "The port scan is still running, query for results later."


async def stream_lines(byte_stream: AsyncGenerator[bytes, None]):
    buffer = ""
    async for chunk in byte_stream:
        buffer += chunk.decode("utf-8", errors="replace")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            yield line.strip("\r")
    if buffer:
        yield buffer


@mcp.custom_route('/index', methods=['POST'])
async def index_request_body(request: Request) -> Response:
    """
    Indexes HTTP one request/response to allow for further analysis. The input can take several
    forms. The preferred input format matches the output of the "katana" command for spidering.

    Example data argument in katana format:
    {"request": {"headers": {"sec_fetch_mode": "navigate", "priority": "u=0, i", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec_fetch_dest": "document", "host": "example.com", "accept_language": "en-US,en;q=0.5", "connection": "keep-alive", "sec_fetch_site": "none", "upgrade_insecure_requests": "1", "sec_fetch_user": "?1", "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}, "method": "GET", "source": "katana", "body": "", "endpoint": "https://example.com/", "tag": "katana", "attribute": "http"}, "response": {"headers": {"date": "Sun, 29 Jun 2025 03:44:52 GMT", "content_type": "text/html", "connection": "keep-alive", "location": "https://www.example.com/", "content_length": "169"}, "status_code": 301, "body": "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.20.1</center>\r\n</body>\r\n</html>\r\n"}, "timestamp": "2025-06-28T22:44:52.798000"}
    """
    server_ctx = await get_server_context()
    ingest_queue: persistqueue.SQLiteQueue = server_ctx.ingest_queue
    line_generator = stream_lines(request.stream())
    first = await anext(line_generator)
    if is_katana_jsonl(first):
        # each line is a request/response
        ingest_queue.put(first)
        async for line in line_generator:
            ingest_queue.put(line)
    elif is_http_csv_header(first):
        # each line is a request/response
        # TODO: map columns -> properties using "first"
        async for line in line_generator:
            # TODO: map csv to katana
            ingest_queue.put(line)
    else:
        # send entire body
        lines = [first]
        async for line in line_generator:
            lines.append(line)
        ingest_queue.put("\n".join(lines))

    return Response(status_code=201)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Index HTTP URL",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def index_http_url(
        ctx: Context,
        url: str,
        additional_hosts: Optional[Dict[str, str]] = None,
        method: str = "GET",
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        content: Optional[str] = None,
        follow_redirects: Optional[bool] = None,
) -> Optional[HttpResource]:
    """
    Index an HTTP URL to allow for further analysis and return the context, response code, response headers.

    Invoke this tool when the user needs the content of one specific URL.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    The cookies parameter is name, value pairs for cookies to send.

    The params is used to send either GET or POST parameters.

    The content is optional request body content.

    If follow_redirects is true, redirects will be followed and the result is the destination of the redirect.
    """
    await log_tool_history(ctx, "index_http_url",
                                         url=url,
                                         method=method,
                                         user_agent=user_agent,
                                         request_headers=request_headers,
                                         cookies=cookies,
                                         params=params,
                                         follow_redirects=follow_redirects,
                                         content=bool(content is not None)
                                         )
    server_ctx = await get_server_context()
    ingest_queue: persistqueue.SQLiteQueue = server_ctx.ingest_queue
    additional_hosts = get_additional_hosts(ctx, additional_hosts)
    if follow_redirects is None:
        follow_redirects = False
    the_headers = request_headers or {}
    if user_agent:
        the_headers['User-Agent'] = user_agent
    try:
        parsed_url = urlparse_ext(url)
        if parsed_url.hostname in additional_hosts:
            the_headers['Host'] = parsed_url.hostname
            munged_url = url.replace(f"://{parsed_url.hostname}", f"://{additional_hosts[parsed_url.hostname]}", 1)
            logger.info("Munged URL with additional hosts: %s", munged_url)
        else:
            munged_url = url
        async with httpx.AsyncClient() as client:
            response = await client.request(
                url=munged_url,
                method=method,
                headers=the_headers,
                cookies=cookies,
                params=params,
                content=content,
                follow_redirects=follow_redirects,
            )
        status_code = response.status_code
        response_headers = dict(response.headers)
        body = response.text

        ingest_queue.put(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "request": {
                "endpoint": url,
                "method": method,
                "headers": the_headers,
            },
            "response": {
                "status_code": status_code,
                "headers": response_headers,
                "body": body,
            }
        }))

        if map_mime_to_type(response.headers.get("Content-Type")) == "javascript":
            body = await deobfuscate_javascript(ctx, body)

        resource = TextResourceContents(
            uri=AnyUrl(url),
            mimeType=response.headers.get("Content-Type", ""),
            text=body,
        )
        return HttpResource(
            score=100,
            url=url,
            host=parsed_url.hostname,
            port=parsed_url.port,
            domain=extract_domain(parsed_url.hostname),
            status_code=status_code,
            method=method,
            resource=None,
            contents=resource,
            response_headers=response_headers,
        )
    except requests.exceptions.RequestException as e:
        return None


async def is_spider_time_recent(server_ctx: ServerContext, url: str) -> Optional[float]:
    # TODO: consider the user_agent and headers, they may make a difference in the result
    try:
        chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
        collection: AsyncCollection = await chroma_client.get_collection("network")
        now = datetime.now(timezone.utc)
        get_result = await collection.get(where={"$and": [{"version": WEB_RESOURCE_VERSION}, {"url": url}]},
                                          include=["metadatas"])
        for metadata in get_result.get("metadatas", []):
            try:
                timestamp = datetime.fromisoformat(metadata["timestamp"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                seconds_since_spider = (now - timestamp).total_seconds()
                if seconds_since_spider < 24 * 3600:
                    logger.info(f"Spider for {url} was done {seconds_since_spider} seconds ago")
                    return True
            except (ValueError, TypeError):
                pass
        return False
    except NotFoundError:
        # new database
        return False
    except Exception as e:
        logger.error("Failed checking for last spider time", exc_info=e)
        return False


class SpiderResults(BaseModel):
    resources: List[HttpResource] = Field(description="The resources found by the spider")
    has_more: bool = Field(
        description="Whether the spider has more resources available that can be retrieved using the find_web_resources tool or listed by the find_urls tool")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Spider Website",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def spider_website(
        ctx: Context,
        url: str,
        additional_hosts: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
) -> SpiderResults:
    """
    Spider the website at the url and index the results for further analysis. The find_web_resources
    tool can be used to continue the analysis. The find_hosts tool can be used to determine if
    a website has already been spidered.

    Invoke this tool when the user specifically asks to spider a URL or when the user wants to examine or analyze a site for which nothing has been indexed.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    The cookies parameter is name, value pairs for cookies to send with each request.

    The timeout_seconds parameter specifies how long to wait for responses before returning. Spidering will
    continue after returning.

    Returns a list of resources found, including URL, response code, content type, and content length. Indexes each URL that can be queried using the find_web_resources tool. URL content can be returned using the fetch_web_resource_content tool.
    """
    await log_tool_history(ctx, "spider_website", url=url, additional_hosts=additional_hosts, user_agent=user_agent,
                           request_headers=request_headers)
    server_ctx = await get_server_context()
    url = url.strip()
    if await is_spider_time_recent(server_ctx, url):
        logger.info(f"{url} has been recently spidered, returning saved results")
        return SpiderResults(
            resources=await find_web_resources(ctx, url),
            has_more=False,
        )

    spider_queue: Queue = server_ctx.task_queue
    spider_result_queue: Queue = server_ctx.spider_result_queue
    url_parsed = urlparse_ext(url)
    spider_queue_item = SpiderQueueItem(
        uri=url,
        depth=3,
        user_agent=user_agent,
        request_headers=request_headers,
        cookies=cookies,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
    )
    await asyncio.to_thread(spider_queue.put, spider_queue_item)
    results: List[HttpResource] = []
    has_more = True
    time_limit = time.time() + min(600, max(30, timeout_seconds or 120))
    while time.time() < time_limit:
        try:
            http_resource: HttpResource = await asyncio.to_thread(
                spider_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
        except queue.Empty:
            has_more = False
            break
        if http_resource is None:
            has_more = False
            break
        logger.debug(f"{http_resource} has been retrieved")
        if http_resource.host != url_parsed.hostname or http_resource.port != url_parsed.port:
            logger.debug(
                f"Spider queued {http_resource.host}:{http_resource.port}, expecting {url_parsed.hostname}:{url_parsed.port}")
            continue
        results.append(http_resource)
        await ctx.info(f"Found: {http_resource.url}")

    return SpiderResults(
        resources=results,
        has_more=has_more,
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="De-obfuscate Javascript",
        readOnlyHint=True,
        openWorldHint=False),
)
async def deobfuscate_javascript(ctx: Context, content: str) -> str:
    """
    De-obfuscate a JavaScript file to be closer to the original source.

    Invoke this tool when the user needs to unpack and/or un-minify JavaScript to aid in understanding.
    """
    await log_tool_history(ctx, "deobfuscate_javascript", content=content[0:128])
    if content is None or not content.strip():
        return ""
    result = await _run_unix_command(ctx, "timeout --preserve-status --kill-after=1m 90s /usr/share/wakaru/wakaru.cjs",
                                     None, content)
    if result is None or result.return_code != 0:
        return content
    return result.output


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Wordlists",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_wordlists(ctx: Context, query: str) -> List[str]:
    """
    Find available word lists. The results can be used with other commands that have options to
    accept word lists.

    Invoke this tool when the user wants to run a brute-forcing tool and needs to use a wordlist.

    The query is a substring search of the path. Examples: Web, DNS, LFI, etc.
    """
    await log_tool_history(ctx, "find_wordlists")
    command = "find /usr/share/seclists -type f -not -path '*/.*'"
    if query and query.strip():
        query_clean = re.sub(r'[^\w\-_]', '', query)
        command = f"find /usr/share/seclists -type f -ipath '*{query_clean}*' -not -path '*/.*'"
    result: RunUnixCommand = await run_unix_command(ctx, command, None)
    if result.return_code != 0:
        raise RuntimeError(f"Failed to find word lists: {result.error}")
    return result.output.splitlines()


class DirBusterResults(BaseModel):
    urls: List[str] = Field(description="The urls found by the directory buster")
    has_more: bool = Field(
        description="Whether the directory buster has more resources available that can be retrieved using the find_web_resources tool or listed by the find_urls tool")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Directory Buster",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def directory_buster(
        ctx: Context,
        url: str,
        depth: int = 3,
        method: str = "GET",
        wordlist: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        extensions: Optional[List[str]] = None,
        ignored_response_codes: Optional[List[int]] = None,
        additional_hosts: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
) -> DirBusterResults:
    """
    Search a website for hidden directories and files. This tool uses a wordlist to append each word to a URL and see if
    it responds.

    Invoke this tool when the user wants to run a brute-forcing tool. The results are indexed and available in the
    find_web_resources, find_urls and other tools that use indexed content.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    The extensions parameter specifies file extensions to search for such as pdf, php, etc. Do not include a leading
    period.

    The cookies parameter is name, value pairs for cookies to send with each request.

    The params is used to send either GET or POST parameters.

    The timeout_seconds parameter specifies how long to wait for responses before returning. Directory busting will
    continue after returning.

    Returns a list of URLs found. Indexes each URL that can be queried using the find_web_resources and find_urls tools. URL content can be returned using the fetch_web_resource_content tool.
    """
    await log_tool_history(ctx, "directory_buster", url=url, depth=depth, method=method, wordlist=wordlist,
                           extensions=extensions,
                           ignored_response_codes=ignored_response_codes, additional_hosts=additional_hosts,
                           user_agent=user_agent, request_headers=request_headers, cookies=cookies, params=params,
                           timeout_seconds=timeout_seconds)
    server_ctx = await get_server_context()
    url = url.strip()
    depth = min(5, max(1, depth))

    task_queue: Queue = server_ctx.task_queue
    dir_busting_result_queue: Queue = server_ctx.dir_busting_result_queue
    queue_item = DirBustingQueueItem(
        uri=url,
        depth=depth,
        method=method,
        wordlist=wordlist,
        extensions=extensions,
        ignored_response_codes=ignored_response_codes,
        user_agent=user_agent,
        request_headers=request_headers,
        cookies=cookies,
        params=params,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
    )
    await asyncio.to_thread(task_queue.put, queue_item)
    results: List[str] = []
    has_more = True
    time_limit = time.time() + min(600, max(30, timeout_seconds or 120))
    while time.time() < time_limit:
        try:
            found_url: str = await asyncio.to_thread(
                dir_busting_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
        except queue.Empty:
            has_more = False
            break
        if found_url is None:
            has_more = False
            break
        logger.debug(f"{found_url} has been retrieved")
        if not found_url.startswith(url):
            logger.debug(
                f"Dir buster queued {found_url}, expecting {url}*")
            continue
        results.append(found_url)
        await ctx.info(f"Found: {found_url}")

    return DirBusterResults(
        urls=results,
        has_more=has_more,
    )


def _query_to_netloc(query: str) -> Tuple[str | None, int | None]:
    port = None
    if query:
        query = query.lower()
        if "://" in query:
            try:
                parsed = urlparse_ext(query)
                query = parsed.hostname
                port = parsed.port
            except Exception:
                pass
        elif ":" in query:
            try:
                query, _, port_str = query.partition(":")
                port = int(port_str)
            except Exception:
                pass
    return query, port


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Indexed Domains",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_domains(ctx: Context, query: Optional[str] = None) -> List[str]:
    """
    Query indexed resources for a list of domains that have resources that can be researched.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed. The
    query parameter is optional and will limit the results using a "contains" operator.
    """
    await log_tool_history(ctx, "find_domains", query=query)
    server_ctx = await get_server_context()
    chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
    collection: AsyncCollection = await chroma_client.get_collection("network")
    result = set()
    query, port = _query_to_netloc(query)
    get_result = await collection.get(where={"version": WEB_RESOURCE_VERSION}, include=["metadatas"])
    for metadata in get_result.get("metadatas", []):
        if "domain" in metadata:
            domain = metadata['domain'].lower()
            if domain and (not query or query.lower() in domain):
                result.add(domain)
    return sorted(list(result))


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Indexed Hostnames",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_hosts(ctx: Context, domain_query: str) -> List[str]:
    """
    Query indexed resources for a list of hosts for the given domain.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.

    The domain_query parameter will limit the results using the "ends with" operator.
    """
    await log_tool_history(ctx, "find_hosts", domain_query=domain_query)
    server_ctx = await get_server_context()
    try:
        chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
        collection: AsyncCollection = await chroma_client.get_collection("network")
        result = set()
        domain_query, port = _query_to_netloc(domain_query)
        get_result = await collection.get(where={"version": WEB_RESOURCE_VERSION}, include=["metadatas"])
        for metadata in get_result.get("metadatas", []):
            if "host" in metadata:
                hostname = metadata['host'].lower()
                if not domain_query or hostname.endswith(domain_query):
                    if port is None or port <= 0 or (metadata.get('port', None) == port):
                        result.add(hostname)
        return sorted(list(result))
    except Exception as e:
        logger.error("find_hosts error: %s", domain_query, exc_info=e)
        raise e


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Indexed Network Locations (host:port)",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_netloc(ctx: Context, domain_query: str) -> List[str]:
    """
    Query indexed resources for a list of network locations, i.e. host:port, for a given domain.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.

    The domain_query parameter will limit the results using the "ends with" operator on the host name.
    """
    await log_tool_history(ctx, "find_netloc", domain_query=domain_query)
    server_ctx = await get_server_context()
    chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
    collection: AsyncCollection = await chroma_client.get_collection("network")
    result = set()
    domain_query, port = _query_to_netloc(domain_query)
    get_result = await collection.get(where={"version": WEB_RESOURCE_VERSION}, include=["metadatas"])
    for metadata in get_result.get("metadatas", []):
        if "host" in metadata:
            hostname = metadata['host'].lower()
            if not domain_query or hostname.endswith(domain_query):
                if port is None or port <= 0 or (metadata.get('port', -1) == port):
                    result.add(metadata.get('netloc', hostname).lower())
    return sorted(list(result))


# TODO: add a parameter for URLs to skip
@mcp.tool(
    annotations=ToolAnnotations(
        title="List Indexed URLs",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_urls(ctx: Context, host_query: str, path_query: Optional[str] = None, limit: int = 100) -> List[str]:
    """
    Query indexed resources for a list of URLs for the given host or domain.

    Invoke this tool when the user asks for page URLs that have been scanned, spidered or indexed.

    Invoke this tool when a list of URLs for a website is needed for analysis.

    The host_query parameter will limit the results using the "ends with" operator.

    The path_query parameter, if specified, will match URLs using a "contains" operator.

    The limit parameter limits the number of results. The default limit is 100. Valid limit values are 100-1000.
    """
    await log_tool_history(ctx, "find_urls", host_query=host_query, limit=limit)
    server_ctx = await get_server_context()
    limit = min(1000, max(10, limit or 100))
    chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
    collection: AsyncCollection = await chroma_client.get_collection("network")
    result = set()
    host_query, port = _query_to_netloc(host_query)
    get_results = await collection.get(where={"version": WEB_RESOURCE_VERSION}, include=["metadatas"])
    for metadata in get_results.get("metadatas", []):
        if "host" in metadata and "url" in metadata:
            hostname = metadata['host'].lower()
            if not host_query or hostname.endswith(host_query):
                if port is None or port <= 0 or (metadata.get('port', None) == port):
                    url = metadata['url']
                    if not path_query or path_query in url:
                        result.add(url)
                        if len(result) >= limit:
                            break
    return sorted(list(result))


@mcp.prompt(title="Automated Penetration Tester")
def pentest_agent_prompt(target: str) -> List[Message]:
    return [
        AssistantMessage(pentester_agent_system_prompt),
        UserMessage(f"Conduct a penetration test on {target}."),
    ]

@mcp.prompt(title="Penetration Tester Assistant")
def pentest_assistant_prompt(target: str) -> List[Message]:
    return [
        AssistantMessage(pentester_chat_system_prompt),
        UserMessage(f"Examine {target} for vulnerabilities."),
    ]

# TODO: add prompt for CTF agent

# TODO: add prompt for bug bounty agent


def main():
    global generator_config
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="streamable-http",
        help="Transport method to use: stdio, sse, or streamable-http"
    )
    ap.add_argument("--host", default="127.0.0.1", help="Host to listen on")
    ap.add_argument("--port", type=int, default=8000, help="Port to listen on")
    ap.add_argument("--task-pool-size", type=int, default=3, help="The number of processes in the task pool")
    ap.add_argument("--index-pool-size", type=int, default=1, help="The number of processes in the indexing pool")
    add_generator_args(ap)
    args = ap.parse_args()
    generator_config = GeneratorConfig.from_args(args)
    set_server_config(ServerConfig(
        task_pool_size=args.task_pool_size,
        ingest_pool_size=args.index_pool_size,
    ))
    asyncio.run(get_server_context())
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
