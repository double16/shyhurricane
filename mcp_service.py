#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import logging
import os
import queue
import subprocess
import sys
import time
import traceback
from collections import deque
from datetime import datetime, timezone
from json import JSONDecodeError
from multiprocessing import Queue, Process
from pathlib import Path
from typing import List, AsyncIterator, Optional, Tuple, Dict, Any, Union
from urllib.parse import urlparse

import chromadb
from chromadb.errors import NotFoundError
import mcp
import requests
import validators
from haystack import Pipeline, Document
from haystack.core.errors import PipelineRuntimeError
from haystack_integrations.document_stores.chroma import ChromaDocumentStore
from mcp import McpError
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation, CancelledElicitation
from mcp.server.fastmcp import FastMCP, Context
from dataclasses import dataclass
from contextlib import asynccontextmanager

from mcp.types import ToolAnnotations, Resource, TextResourceContents
from pydantic import BaseModel, AnyUrl, Field, ValidationError

from ingest_queue import start_ingest_worker
from pipeline import build_document_pipeline, build_website_context_pipeline, urlparse_ext, create_chroma_client
from spider_queue import start_spider_worker, SpiderQueueItem
from utils import HttpResource, latest_mtime, add_generator_args, GeneratorConfig, extract_domain

logger = logging.getLogger(__name__)

generator_config: Optional[GeneratorConfig] = GeneratorConfig.from_env()


@dataclass
class AppContext:
    db: str
    cache_path: str
    document_pipeline: Pipeline
    website_context_pipeline: Pipeline
    ingest_queue: Queue
    ingest_process: Process
    spider_queue: Queue
    spider_result_queue: Queue
    spider_process: Process
    stores: Dict[str, ChromaDocumentStore]
    chroma_client: chromadb.PersistentClient
    top_k: int
    last_mtime: float = None

    def get_cache_path_for_tool(self, tool_id_str: str, additional_hosts: Dict[str, str]) -> str:
        digest = hashlib.sha512()
        digest.update(tool_id_str.encode("utf-8"))
        if additional_hosts:
            digest.update(json.dumps(additional_hosts).encode("utf-8"))
        sha512_str = digest.hexdigest()
        path = os.path.join(self.cache_path, sha512_str[0:2], sha512_str[2:4], sha512_str[4:])
        os.makedirs(path, exist_ok=True)
        return path

    def maybe_reload(self, force=False):
        if not os.path.exists(self.db):
            return
        persist = Path(self.db)
        cur = latest_mtime(persist)
        if self.last_mtime is None:
            self.last_mtime = cur
            return
        if force or cur > self.last_mtime:
            logger.info(f"Reloaded pipeline (modified {int(cur - self.last_mtime)} seconds since last change)")
            self.last_mtime = cur
            document_pipeline, retrievers, stores = build_document_pipeline(
                db=self.db,
                generator_config=generator_config,
            )
            self.document_pipeline = document_pipeline
            self.stores = stores
            self.chroma_client = create_chroma_client(db=self.db)

    def get_document_pipeline(self) -> Pipeline:
        self.maybe_reload()
        return self.document_pipeline

    def get_chroma_client(self) -> chromadb.PersistentClient:
        self.maybe_reload()
        return self.chroma_client


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle with type-safe context"""
    # Initialize on startup
    top_k = max(1, min(1000, int(os.environ.get('TOP_K', '100'))))
    logger.info("Maximum documents is %d", top_k)
    db = os.environ.get('CHROMA', 'chroma_store')
    logger.info("Using chroma database at %s", db)
    chroma_client = create_chroma_client(db=db)
    cache_path = os.path.join(os.environ.get('TOOL_CACHE', os.environ.get('TMPDIR', '/tmp')), 'tool_cache')
    os.makedirs(cache_path, exist_ok=True)
    document_pipeline, retrievers, stores = build_document_pipeline(
        db=db,
        generator_config=generator_config,
    )
    website_context_pipeline = build_website_context_pipeline(
        generator_config=generator_config,
    )
    ingest_queue, ingest_process = start_ingest_worker(db=db, generator_config=generator_config)
    spider_queue, spider_result_queue, spider_process = start_spider_worker(db=db)

    try:
        yield AppContext(
            db=db,
            cache_path=cache_path,
            document_pipeline=document_pipeline,
            website_context_pipeline=website_context_pipeline,
            ingest_queue=ingest_queue,
            ingest_process=ingest_process,
            spider_queue=spider_queue,
            spider_result_queue=spider_result_queue,
            spider_process=spider_process,
            stores=stores,
            chroma_client=chroma_client,
            top_k=top_k,
            last_mtime=time.time(),
        )
    finally:
        # Cleanup on shutdown
        pass


mcp = FastMCP("shyhurricane", lifespan=app_lifespan)


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
                uri=AnyUrl(f"document://{doc.meta['type']}/{doc.id}"),
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
            score=doc.score,
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


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def find_web_resources(query: str) -> List[HttpResource]:
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

    Always include your target URLs. http://target.local is only an example, do not use it as a URL.
    """
    query = query.strip()
    logger.info("finding web resources for %s", query)

    ctx = mcp.get_context()
    document_pipeline: Pipeline = ctx.request_context.lifespan_context.get_document_pipeline()
    website_context_pipeline: Pipeline = ctx.request_context.lifespan_context.website_context_pipeline
    top_k = ctx.request_context.lifespan_context.top_k

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

        store = ctx.request_context.lifespan_context.stores["content"]
        docs = []

        # Make sure the requested URL is returned
        logger.info("Searching for web resources at or below %s", url_prefix)
        filters = {"field": "meta.url", "operator": "in", "value": urls_munged}
        docs.extend(store.filter_documents(filters=filters))

        # Find resources below the URL
        filters = {"field": "meta.netloc", "operator": "==", "value": url_parsed.netloc}
        for doc in store.filter_documents(filters=filters):
            if doc.meta.get("url", "").startswith(url_prefix) and doc.meta.get("url") not in urls_munged:
                docs.append(doc)
            if len(docs) >= top_k:
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
            await ctx.info("Specify a target URL for searching.")
            logger.warning("elicit not supported, exiting", exc_info=e)
            return []

    filter_netloc = [parsed.netloc for parsed in map(lambda u: urlparse_ext(u), urls)]

    # check if we have data
    missing_netloc = set(filter_netloc.copy())
    for known_netloc in find_netloc(None):
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
            await ctx.info(f"Ask to spider {', '.join(missing_urls)}.")
            logger.warning("elicit not supported, continuing")

    conditions = []
    _append_in_filter(conditions, "meta.netloc", filter_netloc)
    _append_in_filter(conditions, "meta.type", doc_types)
    _append_in_filter(conditions, "meta.http_method", methods)
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

    pipeline_retry = 1
    while pipeline_retry > 0:
        pipeline_retry -= 1
        try:
            # TODO: specify top_k
            res = document_pipeline.run(data={"query": {"text": query, "filters": filters}},
                                        include_outputs_from={"combine"})
            documents: List[Document] = res.get("combine", {}).get("documents", [])[0:top_k]
        except PipelineRuntimeError as e:
            if pipeline_retry < 0:
                raise e
            logger.info(f"Retrying pipeline due to {e}")
            # sometimes the chromadb state fails because of writes
            ctx.request_context.lifespan_context.maybe_reload(force=True)
            document_pipeline = ctx.request_context.lifespan_context.get_document_pipeline()

    return _documents_to_http_resources(documents)


async def _find_document_by_type_and_id(doc_type: str, doc_id: str) -> Optional[Document]:
    ctx = mcp.get_context()
    store = ctx.request_context.lifespan_context.stores.get(doc_type, None)
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
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def fetch_web_resource_content(uri: str) -> Optional[TextResourceContents]:
    """Fetch the content of a web resource that has already been indexed. The URI argument takes one of two forms.

    The URI may be an http:// or https:// URI of a website that has been indexed.

    The URI may be a document://{doc_type}/{doc_id} URI supplied by the
    find_web_resources tool. The URI can be found in the resource_link JSON object.

    Invoke this tool when the user requests analysis of resource content that has already been indexed, spidered or scanned.
    """
    doc: Optional[Document] = None
    logger.info("Fetching web resource %s", uri)
    try_http_url = False
    if uri.startswith("document://"):
        doc_type, doc_id = uri.replace("document://", "").split("/", maxsplit=1)
        if "://" in doc_id:
            uri = doc_id
            try_http_url = True
        else:
            doc = await _find_document_by_type_and_id(doc_type, doc_id)
    else:
        try_http_url = True

    if try_http_url:
        ctx = mcp.get_context()
        filters = {"field": "meta.url", "operator": "==", "value": uri}
        store = ctx.request_context.lifespan_context.stores["content"]
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


@mcp.resource("document://{doc_type}/{doc_id}")
async def document_resource(doc_type: str, doc_id: str) -> Optional[TextResourceContents]:
    """
    Fetch a document using the type and document ID.
    """
    doc: Document = await _find_document_by_type_and_id(doc_type, doc_id)
    if doc is None:
        return None
    return TextResourceContents(
        uri=AnyUrl(f"document://{doc_type}/{doc_id}"),
        mimeType=doc.meta.get('content_type', 'text/plain'),
        text=doc.content,
    )


@mcp.prompt(title="Vulnerability Discovery")
def web_vuln(prompt: str) -> str:
    return f"""You are an experienced web‑application pentester. Run query_web_resources with the prompt to obtain crawl/scan artefacts. Identify high‑impact vulnerabilities and exploitation paths.

Question: "{prompt}"
Answer with PoCs/examples. Include the URL for documents that contributed to the answer.
"""


# TODO: persist this? expire entries?
cached_get_additional_hosts: Dict[str, str] = {}


def get_additional_hosts(additional_hosts: Dict[str, str]):
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


@mcp.tool()
async def register_hostname_address(host: str, address: str):
    """
    Registers an IP address with a hostname. This is useful when a hostname has no DNS entry
    but we know the IP address by other means. Especially useful in CTF or private networks.
    """
    get_additional_hosts({host: address})
    return None


class RunCommandConfirmation(BaseModel):
    confirm: bool = Field(description="Should I run this command?", default=True)


class RunUnixCommand(BaseModel):
    return_code: int = Field(description="Return code of command, 0 usually means successful")
    output: str = Field(description="Output of command as string")
    error: str = Field(description="Error messages from the command")
    cached: bool = Field(description="Indicates if the results are from the cache", default=False)
    notes: Optional[str] = Field(description="Notes for understanding the command output or fixing failed commands")


# TODO: consider caching additional hosts, or adding a tool to register them
@mcp.tool()
async def run_unix_command(command: str, additional_hosts: Optional[Dict[str, str]] = None, ctx: Context = None) -> RunUnixCommand:
    """
    Run a Linux or macOS command and return its output. The command is run in a containerized environment for safety.
    The containerized environment is ephemeral. The command is run using the bash shell.
    Progress options should be enabled so that the caller is aware the command is still processing.

    Invoke this tool when the user request can be fulfilled by a known Linux or macOS command line
    program and the request can't be fulfilled by other MCP tools. Invoke this tool when the user
    asks to run a specific command.

    Any commands that take arguments and respond to standard out, and don't require user input are good for this tool.

    The following commands are available: curl, wget, grep, awk, printf, base64, cut, cp, mv, date, factor, gzip, sha256sum, sha512sum, md5sum, echo, seq, true, false, tee, tar, sort, head, tail, ping,
    nmap, rustscan, feroxbuster, gobuster, interactsh-client, katana, nuclei, meg, anew, unfurl, gf, gau, 403jump, waybackurls, httpx, subfinder, gowitness, hakrawler, ffuf, dirb, wfuzz, nc (netcat), graphql-path-enum, evil-winrm,
    DumpNTLMInfo.py, Get,GPPPassword.py, GetADComputers.py, GetADUsers.py, GetLAPSPassword.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, atexec.py, changepasswd.py, dacledit.py, dcomexec.py, describeTicket.py, dpapi.py, esentutl.py, exchanger.py, findDelegation.py, getArch.py, getPac.py, getST.py, getTGT.py, goldenPac.py, karmaSMB.py, keylistattack.py, kintercept.py, lookupsid.py, machine_role.py, mimikatz.py, mqtt_check.py, mssqlclient.py, mssqlinstance.py, net.py, netview.py, ntfs,read.py, ntlmrelayx.py, owneredit.py, ping.py, ping6.py, psexec.py, raiseChild.py, rbcd.py, rdp_check.py, reg.py, registry,read.py, rpcdump.py, rpcmap.py, sambaPipe.py, samrdump.py, secretsdump.py, services.py, smbclient.py, smbexec.py, smbserver.py, sniff.py, sniffer.py, split.py, ticketConverter.py, ticketer.py, tstool.py, wmiexec.py, wmipersist.py, wmiquery.py

    The command 'sudo' is not available.

    The additional_hosts parameter is a mapping of host name to IP address for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The SecLists word lists repository is installed at /usr/share/seclists

    Commands such as nmap can take a long time to run, so be patient.
    """
    try:
        result = await _run_unix_command(command, additional_hosts, ctx)
        return result
    except Exception as e:
        exc_type, exc_value, exc_tb = sys.exc_info()
        return RunUnixCommand(
            return_code=-1,
            output="",
            error=''.join(traceback.format_exception(exc_type, exc_value, exc_tb)),
            notes=None,
        )


async def _run_unix_command(command: str, additional_hosts: Optional[Dict[str, str]], ctx: Context) -> Optional[RunUnixCommand]:
    logger.info(f"run_unix_command {command}")

    cache_path: str = ctx.request_context.lifespan_context.get_cache_path_for_tool(command, additional_hosts)
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
        additional_hosts = get_additional_hosts(additional_hosts)
        for host, ip in additional_hosts.items():
            docker_command.extend(["--add-host", f"{host}:{ip}"])
        docker_command.extend(["shyhurricane_unix_command:latest", "/bin/bash", "-c", command])
        logger.info(f"Executing command {docker_command}")
        with open(stdout_path, "w") as stdout_file:
            with open(stderr_path, "w") as stderr_file:
                last_report = time.time()
                proc = subprocess.Popen(docker_command, shell=False, cwd=cwd, universal_newlines=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                os.set_blocking(proc.stdout.fileno(), False)
                os.set_blocking(proc.stderr.fileno(), False)
                while proc.poll() is None:
                    line_err = proc.stderr.readline()
                    if line_err:
                        stderr_file.write(line_err)

                    line_out = proc.stdout.readline()
                    if line_out:
                        stdout_file.write(line_out)

                    if time.time() - last_report > 5:
                        last_report = time.time()
                        try:
                            await ctx.info(line_err or line_out or "Running")
                        except Exception:
                            pass

                    if not line_err and not line_out:
                        time.sleep(0.2)
                while True:
                    line_err = proc.stderr.readline()
                    if line_err:
                        stderr_file.write(line_err)
                    else:
                        break
                while True:
                    line_out = proc.stdout.readline()
                    if line_out:
                        stdout_file.write(line_out)
                    else:
                        break

        return_code = proc.poll()
        logger.info("Command complete, exit code %d, output size %d, error size %d", return_code,
                    os.stat(stdout_path).st_size, os.stat(stderr_path).st_size)
        meta = {
            "last_run_ts": time.time(),
            "return_code": return_code,
            "command": command,
        }
        with open(meta_path, "w") as meta_file:
            json.dump(meta, meta_file)

    try:
        with open(os.path.join(ctx.request_context.lifespan_context.cache_path, 'history.jsonl'), 'at') as history_file:
            history_file.write(json.dumps({
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "return_code": return_code,
                "additional_hosts": additional_hosts or {},
                "stdout": stdout_path,
                "stderr": stderr_path,
            }))
            history_file.write("\n")
    except IOError as e:
        logger.info("Cannot write to history file", exc_info=e)

    if return_code == 0:
        with open(stdout_path, "r", encoding="utf-8", errors='replace') as f:
            return RunUnixCommand(return_code=return_code, output=f.read(), error="", cached=cached, notes=None)
    else:
        with open(stdout_path, "r", encoding="utf-8", errors='replace') as stdout_file:
            with open(stderr_path, 'r', encoding="utf-8", errors='replace') as stderr_file:
                return RunUnixCommand(
                    return_code=return_code,
                    output=stdout_file.read(),
                    error=''.join(deque(stderr_file, maxlen=20)),
                    cached=cached,
                    notes=None,
                )


@mcp.tool()
async def index_http_request_response(data: str):
    """
    Indexes HTTP one request/response to allow for further analysis. The input can take several
    forms. The preferred input format matches the output of the "katana" command for spidering.

    Example data argument in katana format:
    {"request": {"headers": {"sec_fetch_mode": "navigate", "priority": "u=0, i", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec_fetch_dest": "document", "host": "example.com", "accept_language": "en-US,en;q=0.5", "connection": "keep-alive", "sec_fetch_site": "none", "upgrade_insecure_requests": "1", "sec_fetch_user": "?1", "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}, "method": "GET", "source": "katana", "body": "", "endpoint": "https://example.com/", "tag": "katana", "attribute": "http"}, "response": {"headers": {"date": "Sun, 29 Jun 2025 03:44:52 GMT", "content_type": "text/html", "connection": "keep-alive", "location": "https://www.example.com/", "content_length": "169"}, "status_code": 301, "body": "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.20.1</center>\r\n</body>\r\n</html>\r\n"}, "timestamp": "2025-06-28T22:44:52.798000"}
    """
    ctx = mcp.get_context()
    ingest_queue: Queue = ctx.request_context.lifespan_context.ingest_queue
    ingest_queue.put_nowait(data)
    return None


def parse_http_response(response_text) -> Tuple[
    Optional[int],
    Dict[str, Union[str, list[str]]],
    str]:
    lines = response_text.splitlines()
    headers = {}
    body_lines = []
    in_headers = True
    status_code = None

    for i, line in enumerate(lines):
        if in_headers:
            if line.strip() == "":
                in_headers = False
                continue
            if line.startswith("HTTP/"):
                try:
                    status_code = int(line.split()[1])
                except (IndexError, ValueError):
                    status_code = None
            else:
                key, sep, value = line.partition(":")
                if sep:
                    key = key.strip().title()
                    value = value.strip()
                    # handle multiple headers like set-cookie
                    if key in headers:
                        if isinstance(headers[key], list):
                            headers[key].append(value)
                        else:
                            headers[key] = [headers[key], value]
                    else:
                        headers[key] = value
        else:
            body_lines.append(line)

    body = "\n".join(body_lines)
    return status_code, headers, body


@mcp.tool()
async def index_http_url(
        url: str,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        # TODO: add more curl-like options
) -> Optional[HttpResource]:
    """
    Index an HTTP URL to allow for further analysis and return the context, response code, response headers.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    Invoke this tool when the user needs the content of one specific URL.
    """
    logger.info("indexing HTTP URL %s", url)
    the_headers = request_headers or {}
    if user_agent:
        the_headers['User-Agent'] = user_agent
    try:
        parsed_url = urlparse_ext(url)
        response = requests.get(url, headers=the_headers)
        status_code = response.status_code
        headers = dict(response.headers)
        body = response.text
        await index_http_request_response(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "request": {
                "endpoint": url,
            },
            "response": {
                "status_code": status_code,
                "headers": headers,
                "body": body,
            }
        }))
        resource = TextResourceContents(
            uri=AnyUrl(url),
            mimeType=headers.get("Content-Type", "text/plain"),
            text=body,
        )
        return HttpResource(
            score=100,
            url=url,
            host=parsed_url.hostname,
            port=parsed_url.port,
            domain=extract_domain(parsed_url.hostname),
            status_code=status_code,
            method="GET",
            resource=None,
            contents=resource,
            response_headers=headers,
        )
    except requests.exceptions.RequestException as e:
        return None


def is_spider_time_recent(url: str) -> Optional[float]:
    # TODO: consider the user_agent and headers, they may make a difference in the result
    try:
        ctx = mcp.get_context()
        chroma_client: chromadb.PersistentClient = ctx.request_context.lifespan_context.get_chroma_client()
        collection: chromadb.Collection = chroma_client.get_collection("network")
        url_parsed = urlparse_ext(url)
        netloc = url_parsed.netloc
        now = datetime.now(timezone.utc)
        for metadata in collection.get(where={"netloc": netloc}, include=["metadatas"]).get("metadatas", []):
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


@mcp.tool()
async def spider_website(url: str,
                         additional_hosts: Optional[Dict[str, str]] = None,
                         user_agent: Optional[str] = None,
                         request_headers: Optional[Dict[str, str]] = None) -> SpiderResults:
    """
    Spider the website at the url and index the results for further analysis. The find_web_resources
    tool can be used to continue the analysis. The find_hosts tool can be used to determine if
    a website has already been spidered.

    Invoke this tool when the user specifically asks to spider a URL or when the user wants to examine or analyze a site for which nothing has been indexed.

    The additional_hosts parameter is a mapping of host name to IP address for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    Returns a list of resources found, including URL, response code, content type, and content length. Indexes each URL that can be queried using the find_web_resources tool. URL content can be returned using the fetch_web_resource_content tool.
    """
    url = url.strip()
    if is_spider_time_recent(url):
        logger.info(f"{url} has been recently spidered, returning saved results")
        return SpiderResults(
            resources=await find_web_resources(url),
            has_more=False,
        )

    ctx = mcp.get_context()
    spider_queue: Queue = ctx.request_context.lifespan_context.spider_queue
    spider_result_queue: Queue = ctx.request_context.lifespan_context.spider_result_queue
    url_parsed = urlparse_ext(url)
    spider_queue_item = SpiderQueueItem(
        uri=url,
        depth=3,
        user_agent=user_agent,
        request_headers=request_headers,
        additional_hosts=get_additional_hosts(additional_hosts),
    )
    spider_queue.put_nowait(spider_queue_item)
    results: List[HttpResource] = []
    time_limit = time.time() + 90
    while time.time() < time_limit:
        try:
            http_resource: HttpResource = spider_result_queue.get(
                block=True,
                timeout=(max(1.0, time_limit - time.time())))
        except queue.Empty:
            break
        if http_resource is None:
            break
        if http_resource.host != url_parsed.hostname or http_resource.port != url_parsed.port:
            continue
        results.append(http_resource)
        await ctx.info(f"Found: {http_resource.url}")

    return SpiderResults(
        resources=results,
        has_more=time.time() >= time_limit,
    )


# TODO: add port scanning tool that controls options for nmap for our use case and store in document

# TODO: add tool to fetch port scan results

@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def find_wordlists() -> List[str]:
    """
    Find available word lists. The results can be used with other commands that have options to
    accept word lists.

    Invoke this tool when the user wants to run a brute-forcing tool and needs to use a wordlist.
    """
    result: RunUnixCommand = await run_unix_command("find /usr/share/seclists -type f", None, mcp.get_context())
    if result.return_code != 0:
        raise RuntimeError(f"Failed to find word lists: {result.error}")
    return result.output.splitlines()


# TODO: add busting tool (using feroxbuster), and prompt


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
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def find_domains(query: Optional[str] = None) -> List[str]:
    """
    Query indexed resources for a list of domains that have resources that can be researched.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed. The
    query parameter is optional and will limit the results using a "contains" operator.
    """
    ctx = mcp.get_context()
    chroma_client: chromadb.PersistentClient = ctx.request_context.lifespan_context.get_chroma_client()
    collection: chromadb.Collection = chroma_client.get_collection("network")
    result = set()
    query, port = _query_to_netloc(query)
    for metadata in collection.get(include=["metadatas"]).get("metadatas", []):
        if "domain" in metadata:
            domain = metadata['domain'].lower()
            if not query or query.lower() in domain:
                result.add(domain)
    return sorted(list(result))


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True),
)
def find_hosts(domain_query: str) -> List[str]:
    """
    Query indexed resources for a list of hosts for the given domain.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.

    The domain_query parameter will limit the results using the "ends with" operator.
    """
    try:
        ctx = mcp.get_context()
        chroma_client: chromadb.PersistentClient = ctx.request_context.lifespan_context.get_chroma_client()
        collection: chromadb.Collection = chroma_client.get_collection("network")
        result = set()
        domain_query, port = _query_to_netloc(domain_query)
        for metadata in collection.get(include=["metadatas"]).get("metadatas", []):
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
    annotations=ToolAnnotations(readOnlyHint=True),
)
def find_netloc(domain_query: str) -> List[str]:
    """
    Query indexed resources for a list of network locations, i.e. host:port, for a given domain.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.

    The domain_query parameter will limit the results using the "ends with" operator on the host name.
    """
    ctx = mcp.get_context()
    chroma_client: chromadb.PersistentClient = ctx.request_context.lifespan_context.get_chroma_client()
    collection: chromadb.Collection = chroma_client.get_collection("network")
    result = set()
    domain_query, port = _query_to_netloc(domain_query)
    for metadata in collection.get(include=["metadatas"]).get("metadatas", []):
        if "host" in metadata:
            hostname = metadata['host'].lower()
            if not domain_query or hostname.endswith(domain_query):
                if port is None or port <= 0 or (metadata.get('port', None) == port):
                    result.add(metadata.get('netloc', hostname).lower())
    return sorted(list(result))


# TODO: add a parameter for URLs to skip
@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def find_urls(host_query: str, limit: int = 100) -> List[str]:
    """
    Query indexed resources for a list of URLs for the given host or domain.

    Invoke this tool when the user asks for page URLs that have been scanned, spidered or indexed.

    Invoke this tool when a list of URLs for a website is needed for analysis.

    The host_query parameter will limit the results using the "ends with" operator.

    The limit parameter limits the number of results. The default limit is 100.
    """
    assert limit > 0
    ctx = mcp.get_context()
    chroma_client: chromadb.PersistentClient = ctx.request_context.lifespan_context.get_chroma_client()
    collection: chromadb.Collection = chroma_client.get_collection("network")
    result = set()
    host_query, port = _query_to_netloc(host_query)
    for metadata in collection.get(include=["metadatas"]).get("metadatas", []):
        if "host" in metadata and "url" in metadata:
            hostname = metadata['host'].lower()
            if not host_query or hostname.endswith(host_query):
                if port is None or port <= 0 or (metadata.get('port', None) == port):
                    result.add(metadata["url"])
                    if len(result) >= limit:
                        break
    return sorted(list(result))


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
    add_generator_args(ap)
    args = ap.parse_args()
    generator_config = GeneratorConfig.from_args(args)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
