import asyncio
import json
import logging
import queue
import time
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import Annotated, Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

from haystack import Document, Pipeline
from mcp import MCPError, Resource
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation, ElicitationResult
from mcp.server.mcpserver import Context, Elicit, Resolve
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from mcp.types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel, Field
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm

from shyhurricane.db import scroll_qdrant_collection
from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server import (
    AdditionalHostsField,
    CookiesField,
    RequestHeadersField,
    ServerContext,
    UserAgentField,
    assert_elicitation,
    get_additional_hosts,
    get_additional_http_headers,
    get_server_context,
    log_tool_history,
    mcp_instance,
)
from shyhurricane.mcp_server.progress import progress_scope, report_progress
from shyhurricane.mcp_server.tools.find_indexed_metadata import find_netloc
from shyhurricane.predicate_search import candidate_filters, load_candidates, select_candidates
from shyhurricane.rate_limit import get_rate_limit_requests_per_second
from shyhurricane.search_predicates import Predicate, parse_predicates
from shyhurricane.server_config import get_server_config
from shyhurricane.target_info import TargetInfo, filter_targets_query, parse_target_info
from shyhurricane.task_queue import SpiderQueueItem
from shyhurricane.task_queue.types import SpiderResultItem
from shyhurricane.utils import (
    HttpResource,
    coerce_to_dict,
    coerce_to_list,
    documents_sort_unique,
    extract_domain,
    filter_hosts_and_addresses,
    munge_urls,
    query_to_netloc,
    urlparse_ext,
)

logger = logging.getLogger(__name__)


class RequestTargetUrl(BaseModel):
    data: str = Field(default="", description="URL(s), content types, technology of interest")


def _append_in_filter(conditions: List[Dict[str, Any]], field: str, values: List[str]):
    values2 = list(filter(lambda e: e is not None, values))
    if len(values2) == 1:
        conditions.append({"field": field, "operator": "==", "value": values2[0]})
    elif len(values2) > 1:
        conditions.append({"field": field, "operator": "in", "value": values2})


def _documents_to_http_resources(documents: List[Document]) -> List[HttpResource]:
    https_resources = []
    for doc in documents:
        if doc.content and 'url' in doc.meta and 'type' in doc.meta:
            resource = Resource(
                name=doc.meta['url'],
                title=doc.meta.get('title', None),
                description=doc.meta.get('description', None),
                uri=f"web://{doc.meta['type']}/{doc.id}",
                mime_type=doc.meta.get('content_type', 'text/plain'),
                size=len(doc.content),
            )
        else:
            resource = None

        https_resources.append(HttpResource.from_doc(doc, resource=resource))
    return https_resources


async def _find_web_resources_by_url(ctx: Context, query: str, limit: int = 100) -> Optional[List[HttpResource]]:
    server_ctx = await get_server_context()
    try:
        url_parsed = urlparse_ext(query)
        url_prefix, urls_munged = munge_urls(query)

        store = server_ctx.stores["content"]
        docs = []

        # Make sure the requested URL is returned
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.url", "operator": "in", "value": urls_munged}
            ]}
        logger.info("Searching for web resources at or below %s using filters %s", url_prefix, filters)
        docs.extend(await store.filter_documents_async(filters=filters))

        # Find resources below the URL
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.netloc", "operator": "==", "value": url_parsed.netloc}
            ]}
        logger.info("Searching for web resources at or below %s using filters %s", url_prefix, filters)
        for doc in await store.filter_documents_async(filters=filters):
            if doc.meta.get("url", "").startswith(url_prefix) and doc.meta.get("url") not in urls_munged:
                docs.append(doc)

        logger.info("Found %d documents", len(docs))
        docs = documents_sort_unique(docs, limit)

        if docs:
            return _documents_to_http_resources(docs)
    except Exception:
        pass

    return None


async def _find_web_resources_by_netloc(ctx: Context, query: str, limit: int = 100) -> Optional[List[HttpResource]]:
    server_ctx = await get_server_context()
    try:
        hostname, port = query_to_netloc(query)
        if hostname is None or port is None:
            return None
        if not filter_hosts_and_addresses([hostname]):
            return None
        store = server_ctx.stores["content"]
        docs = []

        # Make sure the requested URL is returned
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.netloc", "operator": "==", "value": query}
            ]}
        logger.info("Searching for web resources for %s using filters %s", query, filters)
        docs.extend(await store.filter_documents_async(filters=filters))

        logger.info("Found %d documents", len(docs))
        docs = documents_sort_unique(docs, limit)

        if docs:
            return _documents_to_http_resources(docs)
    except Exception:
        pass

    return None


async def _find_web_resources_by_hostname(ctx: Context, query: str, limit: int = 100) -> Optional[List[HttpResource]]:
    server_ctx = await get_server_context()
    try:
        hostname, port = query_to_netloc(query)
        if hostname is None or port is not None:
            return None
        if not filter_hosts_and_addresses([hostname]):
            return None
        store = server_ctx.stores["content"]
        docs = []

        # Make sure the requested URL is returned
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                {"field": "meta.host", "operator": "==", "value": hostname}
            ]}
        logger.info("Searching for web resources for %s using filters %s", query, filters)
        docs.extend(await store.filter_documents_async(filters=filters))

        logger.info("Found %d documents", len(docs))
        docs = documents_sort_unique(docs, limit)

        if docs:
            return _documents_to_http_resources(docs)
    except Exception:
        pass

    return None


async def _find_recommended_urls(ctx: Context) -> Optional[List[str]]:
    net_locs = (await find_netloc(ctx, "")).network_locations
    if not net_locs:
        return None
    domains = set(map(lambda n: extract_domain(n.split(':')[0]), net_locs))
    if len(domains) != 1:
        return None
    results = []
    for netloc in net_locs:
        hostname, port = query_to_netloc(netloc)
        if port % 1000 == 443:
            results.append(f"https://{hostname}:{port}")
        elif not port:
            results.append(f"http://{hostname}")
        else:
            results.append(f"http://{hostname}:{port}")

    logger.info("Recommended URLs: %s", results)

    return results


class FindWebResourcesResult(BaseModel):
    instructions: str = Field(description="Instructions for using the results")
    query: str = Field(description="Search query used to find web resources")
    http_methods: Optional[List[str]] = Field(default=None, description="HTTP methods used to find web resources")
    limit: int = Field(description="Maximum number of results returned")
    resources: List[HttpResource] = Field(default_factory=list, description="List of web resources found")


find_web_resources_instructions = "These resources were found by searching the indexed resources using the given query."
find_web_resources_instructions_not_found = (
    "No documents are indexed for the requested target. Use the spider_website, "
    "directory_buster or index_http_url tools to populate the index."
)
find_web_resources_instructions_no_matches = (
    "No indexed resources matched the query. Try broadening the query or relaxing its filters."
)
find_web_resources_instructions_need_target = "Include a target URL, IP address or hostname in query."
find_web_resources_instructions_low_power = "No indexed resources were considered due to low power mode. Include only hostnames, IP addresses or URLs in the query."


def find_web_resources_result(
        query: str,
        http_methods: Optional[List[str]],
        limit: int,
        results: List[HttpResource],
        target_indexed: bool = True,
) -> FindWebResourcesResult:
    return FindWebResourcesResult(
        instructions=find_web_resources_instructions if results else (
            find_web_resources_instructions_no_matches if target_indexed else find_web_resources_instructions_not_found
        ),
        query=query,
        http_methods=http_methods,
        limit=limit,
        resources=results,
    )


class SpiderConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm spider?", default=False)


@dataclass
class SearchPreparation:
    query: str
    limit: int
    http_methods: Optional[List[str]]
    server_ctx: ServerContext
    doc_types: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    response_codes: list[int] = field(default_factory=list)
    filter_netloc: list[str] = field(default_factory=list)
    filter_domain: set[str] = field(default_factory=set)
    missing_targets: list[TargetInfo] = field(default_factory=list)
    predicates: list[Predicate] = field(default_factory=list)
    semantic_query: Optional[str] = None
    has_indexed_targets: bool = False


async def _determine_targets(ctx: Context, search: SearchPreparation, target_query: str):
    await report_progress(ctx, "Determining target(s)")
    result = await search.server_ctx.website_context_pipeline.run_async({"builder": {"query": target_query}})
    reply = result.get("llm", {}).get("replies", [""])[0]
    if reply:
        try:
            data = json.loads(reply)
            search.targets.extend(data.get("target", []))
            search.doc_types.extend(data.get("content", []))
            search.response_codes.extend(data.get("response_codes", []))
        except json.JSONDecodeError:
            pass


async def _prepare_search(
    ctx: Context,
    query: str,
    limit: int,
    http_methods: Optional[Union[List[str], str]],
) -> Union[SearchPreparation, FindWebResourcesResult]:
    # coerce types
    http_methods = coerce_to_list(http_methods)

    server_ctx = await get_server_context()
    query = query.strip()
    limit = min(1000, max(10, limit or 100))
    logger.info("finding web resources for %s up to %d results", query, limit)

    try:
        semantic_query, predicates = parse_predicates(query)
    except ValueError as error:
        raise ToolError(f"Invalid search predicate: {error}") from error
    if predicates:
        search = SearchPreparation(query, limit, http_methods, server_ctx,
                                   predicates=predicates, semantic_query=semantic_query)
        sites = [predicate.value for predicate in predicates if predicate.operator == "site" and not predicate.exclude]
        low_power = server_ctx.low_power
        if semantic_query:
            if low_power:
                return FindWebResourcesResult(
                    instructions=find_web_resources_instructions_low_power,
                    query=query, http_methods=http_methods, limit=limit,
                )
            await server_ctx.ensure_retrieval_pipelines()
            if server_ctx.website_context_pipeline is None or server_ctx.document_pipeline is None:
                return FindWebResourcesResult(
                    instructions=find_web_resources_instructions_low_power,
                    query=query, http_methods=http_methods, limit=limit,
                )
            await _determine_targets(ctx, search, semantic_query)
        if sites:
            search.targets = sites
        if not search.targets:
            search.targets.extend(await _find_recommended_urls(ctx) or [])
        return search

    if resources_by_url := await _find_web_resources_by_url(ctx, query, limit):
        return find_web_resources_result(results=resources_by_url, query=query, http_methods=http_methods, limit=limit)
    if resources_by_netloc := await _find_web_resources_by_netloc(ctx, query, limit):
        return find_web_resources_result(
            results=resources_by_netloc, query=query, http_methods=http_methods, limit=limit
        )
    if resources_by_hostname := await _find_web_resources_by_hostname(ctx, query, limit):
        return find_web_resources_result(
            results=resources_by_hostname, query=query, http_methods=http_methods, limit=limit
        )

    low_power = getattr(server_ctx, "low_power", None)
    if low_power is None:
        low_power = get_server_config().low_power

    if low_power:
        logger.warning("low_power: embedding based-retrieval disabled")
        return FindWebResourcesResult(
            instructions=find_web_resources_instructions_low_power,
            query=query,
            http_methods=http_methods,
            limit=limit,
            resources=[],
        )

    if hasattr(server_ctx, "ensure_retrieval_pipelines"):
        await server_ctx.ensure_retrieval_pipelines()

    document_pipeline: Optional[Pipeline] = server_ctx.document_pipeline
    website_context_pipeline: Optional[Pipeline] = server_ctx.website_context_pipeline

    if website_context_pipeline is None or document_pipeline is None:
        logger.warning("low_power: embedding based-retrieval disabled")
        return FindWebResourcesResult(
            instructions=find_web_resources_instructions_low_power,
            query=query,
            http_methods=http_methods,
            limit=limit,
            resources=[],
        )

    search = SearchPreparation(query, limit, http_methods, server_ctx)
    await _determine_targets(ctx, search, query)
    if not search.targets:
        search.targets.extend(await _find_recommended_urls(ctx) or [])
    return search


def _can_elicit(ctx: Context, server_ctx: ServerContext) -> bool:
    if server_ctx.disable_elicitation:
        return False
    if ctx.protocol_version not in MODERN_PROTOCOL_VERSIONS and not ctx.session.can_send_request:
        return False
    capabilities = ctx.session.client_capabilities
    return (
        capabilities is not None
        and capabilities.elicitation is not None
        and (capabilities.elicitation.form is not None)
    )


async def _request_target(
    ctx: Context,
    search: Annotated[Union[SearchPreparation, FindWebResourcesResult], Resolve(_prepare_search)],
) -> Union[RequestTargetUrl, Elicit[RequestTargetUrl]]:
    if isinstance(search, FindWebResourcesResult) or search.targets:
        return RequestTargetUrl()
    if not _can_elicit(ctx, search.server_ctx):
        return RequestTargetUrl()
    return Elicit("What URL(s) should we look for?", RequestTargetUrl)


async def _prepare_targets(
    ctx: Context,
    search: Annotated[Union[SearchPreparation, FindWebResourcesResult], Resolve(_prepare_search)],
    target_answer: Annotated[ElicitationResult[RequestTargetUrl], Resolve(_request_target)],
) -> Union[SearchPreparation, FindWebResourcesResult]:
    if isinstance(search, FindWebResourcesResult):
        return search
    if not search.targets and isinstance(target_answer, AcceptedElicitation) and target_answer.data.data:
        if search.predicates and not search.semantic_query:
            search.targets.extend(filter_targets_query(target_answer.data.data))
        else:
            await _determine_targets(ctx, search, target_answer.data.data)
    if not search.targets:
        return FindWebResourcesResult(
            instructions=find_web_resources_instructions_need_target,
            query=search.query,
            http_methods=search.http_methods,
            limit=search.limit,
        )
    targets = search.targets
    sites = [predicate for predicate in search.predicates if predicate.operator == "site" and not predicate.exclude]
    if sites:
        # Resolve host scope independently of the legacy parent-domain fallback.
        known = (await find_netloc(ctx, "")).network_locations
        search.has_indexed_targets = any(site.matches_netloc(netloc) for site in sites for netloc in known)
        search.filter_netloc = [netloc for netloc in known if all(site.matches_netloc(netloc) for site in sites)]
        if not search.filter_netloc:
            # Distinguish an absent target from contradictory site constraints.
            for site in sites:
                target = urlsplit(site.value if "://" in site.value else f"//{site.value}")
                host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
                if not any(site.matches_netloc(netloc) for netloc in known):
                    search.missing_targets.append(TargetInfo(
                        url=site.value if target.scheme else (
                            f"http://{target.netloc}" if ":" in target.hostname else None
                        ),
                        host=target.hostname, port=target.port,
                        netloc=f"{host}:{target.port}" if target.port else None,
                        domain=extract_domain(target.hostname),
                    ))
        return search
    parsed_targets: List[TargetInfo] = []
    for target in targets:
        try:
            raw_target = parse_target_info(target)
            if not raw_target.netloc and raw_target.host:
                parsed_targets.append(raw_target.with_port(80))
                parsed_targets.append(raw_target.with_port(443))
            else:
                parsed_targets.append(raw_target)
        except ValueError:
            pass
    filter_netloc = list(map(lambda t: t.netloc, parsed_targets))
    filter_domain = set()

    # check if we have data
    missing_netloc = set(filter_netloc.copy())
    known_netlocs = (await find_netloc(ctx, "")).network_locations
    search.has_indexed_targets = any(
        known_netloc in filter_netloc or any(
            known_netloc.split(":")[0].endswith("." + target.host) for target in parsed_targets
        )
        for known_netloc in known_netlocs
    )
    for known_netloc in known_netlocs:
        try:
            missing_netloc.remove(known_netloc)
        except KeyError:
            for target in parsed_targets:
                if known_netloc.split(":")[0].endswith("." + target.host):
                    filter_domain.add(target.host)
        if len(missing_netloc) == 0:
            break
    missing_targets: List[TargetInfo] = []
    # if we're missing network locations but we have domains, do a domain filter
    if missing_netloc and filter_domain:
        missing_netloc.clear()
        filter_netloc.clear()
    else:
        for target in parsed_targets:
            if target.netloc in missing_netloc:
                missing_targets.append(target)
    search.filter_netloc = filter_netloc
    search.filter_domain = filter_domain
    search.missing_targets = missing_targets
    return search


async def _request_scan(
    ctx: Context,
    search: Annotated[Union[SearchPreparation, FindWebResourcesResult], Resolve(_prepare_targets)],
) -> Union[SpiderConfirmation, Elicit[SpiderConfirmation]]:
    if isinstance(search, FindWebResourcesResult) or not search.missing_targets or not search.server_ctx.open_world:
        return SpiderConfirmation(confirm=False)
    if not _can_elicit(ctx, search.server_ctx):
        return SpiderConfirmation(confirm=False)
    targets = ", ".join(map(str, search.missing_targets))
    return Elicit(f"There is no data for {targets}. Would you like to start a scan?", SpiderConfirmation)


async def _execute_search(
    ctx: Context,
    search: Union[SearchPreparation, FindWebResourcesResult],
    scan_answer: ElicitationResult[SpiderConfirmation],
) -> FindWebResourcesResult:
    if isinstance(search, FindWebResourcesResult):
        return search
    query, limit, http_methods = search.query, search.limit, search.http_methods
    await log_tool_history(ctx, "find_web_resources", query=query, limit=limit)
    if search.missing_targets:
        if (
            not search.server_ctx.open_world
            or not isinstance(scan_answer, AcceptedElicitation)
            or not scan_answer.data.confirm
        ):
            if not search.has_indexed_targets:
                return find_web_resources_result(query, http_methods, limit, [], target_indexed=False)
        else:
            for target in search.missing_targets:
                await spider_website(ctx, target.to_url())
            # A completed scan may have queued documents that are not searchable yet.
            search.has_indexed_targets = True
            if search.predicates:
                search.filter_netloc.clear()
                search.missing_targets.clear()
                await _prepare_targets(ctx, search, AcceptedElicitation(data=RequestTargetUrl()))
    filter_netloc, filter_domain = search.filter_netloc, search.filter_domain
    methods, response_codes, doc_types = http_methods or [], search.response_codes, search.doc_types
    targets = search.targets
    document_pipeline = search.server_ctx.document_pipeline
    if search.predicates:
        return await _execute_predicate_search(ctx, search)
    conditions = [{"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION}]
    if filter_netloc:
        _append_in_filter(conditions, "meta.netloc", filter_netloc)
    elif filter_domain:
        _append_in_filter(conditions, "meta.domain", list(filter_domain))
    # _append_in_filter(conditions, "meta.type", doc_types) # tends to be too limiting
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

    logger.info(f"Searching for {', '.join(targets)} with filter {repr(filters)}")
    await report_progress(ctx, f"Searching for {', '.join(targets)}")

    loop = asyncio.get_running_loop()

    def progress_callback(message: str):
        try:
            asyncio.run_coroutine_threadsafe(report_progress(ctx, message), loop).result()
        except Exception as e:
            logger.warning(f"Error reporting progress: {e}")

    async with asyncio.timeout(300):
        res = await asyncio.to_thread(
            document_pipeline.run,
            data={
                "query": {
                    "text": query,
                    "filters": filters,
                    "max_results": limit,
                    "targets": filter_netloc + list(filter_domain),
                    "doc_types": doc_types,
                    "progress_callback": progress_callback,
                }
            },
            include_outputs_from={"combine"},
        )

    documents = documents_sort_unique(res.get("combine", {}).get("documents", []), limit)

    logger.info(f"Found {len(documents)} documents")

    return find_web_resources_result(
        results=_documents_to_http_resources(documents), query=query, http_methods=http_methods, limit=limit,
        target_indexed=search.has_indexed_targets,
    )


async def _execute_predicate_search(ctx: Context, search: SearchPreparation) -> FindWebResourcesResult:
    explicit_sites = any(predicate.operator == "site" and not predicate.exclude for predicate in search.predicates)
    if explicit_sites and not search.filter_netloc:
        return find_web_resources_result(
            search.query, search.http_methods, search.limit, [], target_indexed=search.has_indexed_targets,
        )
    must = [qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION))]
    if search.filter_netloc:
        must.append(qm.FieldCondition(key="meta.netloc", match=qm.MatchAny(any=search.filter_netloc)))
    elif search.filter_domain:
        must.append(qm.FieldCondition(key="meta.domain", match=qm.MatchAny(any=list(search.filter_domain))))
    predicates = search.predicates.copy()
    if search.response_codes and not any(predicate.operator == "status" for predicate in predicates):
        must.append(qm.FieldCondition(key="meta.status_code", match=qm.MatchAny(any=search.response_codes)))

    async def progress(message):
        await report_progress(ctx, message)

    methods = [method.upper() for method in search.http_methods or []]
    client = search.server_ctx.qdrant_client
    async with asyncio.timeout(300):
        collections = [collection.name for collection in (await client.get_collections()).collections]
        selected = await select_candidates(client, collections, predicates, qm.Filter(must=must), methods, progress)
        if not search.semantic_query:
            documents = await load_candidates(client, selected, search.limit)
        elif not any(selected.values()):
            documents = []
        else:
            loop = asyncio.get_running_loop()

            def progress_callback(message):
                asyncio.run_coroutine_threadsafe(progress(message), loop).result()

            result = await asyncio.to_thread(
                search.server_ctx.document_pipeline.run,
                data={"query": {
                    "text": search.semantic_query,
                    "filters": {"predicate_filters": candidate_filters(selected)},
                    "max_results": search.limit,
                    "targets": search.filter_netloc + list(search.filter_domain),
                    "doc_types": search.doc_types,
                    "progress_callback": progress_callback,
                }},
                include_outputs_from={"combine"},
            )
            documents = documents_sort_unique(result.get("combine", {}).get("documents", []), search.limit)
    return find_web_resources_result(
        search.query, search.http_methods, search.limit, _documents_to_http_resources(documents),
        target_indexed=search.has_indexed_targets,
    )


@progress_scope()
async def find_web_resources(
    ctx: Context,
    query: str,
    limit: int = 100,
    http_methods: Optional[Union[List[str], str]] = None,
) -> FindWebResourcesResult:
    """Run indexed retrieval directly inside another tool's existing request."""
    search = await _prepare_search(ctx, query, limit, http_methods)
    if isinstance(search, FindWebResourcesResult):
        return search
    answer = AcceptedElicitation(data=RequestTargetUrl())
    if not search.targets:
        try:
            assert_elicitation(search.server_ctx)
            answer = await ctx.elicit("What URL(s) should we look for?", RequestTargetUrl)
        except MCPError:
            answer = DeclinedElicitation()
    search = await _prepare_targets(ctx, search, answer)
    scan_answer = DeclinedElicitation()
    if isinstance(search, SearchPreparation) and search.missing_targets and search.server_ctx.open_world:
        try:
            assert_elicitation(search.server_ctx)
            targets = ", ".join(map(str, search.missing_targets))
            scan_answer = await ctx.elicit(
                f"There is no data for {targets}. Would you like to start a scan?",
                SpiderConfirmation,
            )
        except MCPError:
            pass
    return await _execute_search(ctx, search, scan_answer)


@mcp_instance.tool(
    name="find_web_resources",
    annotations=ToolAnnotations(title="Find Web Resources", read_only_hint=True, open_world_hint=False),
)
async def find_web_resources_tool(
    ctx: Context,
    query: str,
    search: Annotated[Union[SearchPreparation, FindWebResourcesResult], Resolve(_prepare_targets)],
    scan_answer: Annotated[ElicitationResult[SpiderConfirmation], Resolve(_request_scan)],
    limit: Annotated[int, Field(100, description="Limit how many results are returned", ge=10, le=1000)] = 100,
    http_methods: Annotated[
        Optional[Union[List[str], str]],
        Field(
            description="Limit results to requests made with the listed HTTP methods. If not specified all methods will be considered."
        ),
    ] = None,
) -> FindWebResourcesResult:
    """Query indexed resources about a website using natural language and return the URL, request and response bodies,
    request and response headers, HTTP method, MIME type, HTTP status code, technologies found. This tool will
    search using several parameters including response body matching, URL matching, MIME type matching of the response,
    and HTTP response body matching.

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

    Optional hard filters: site:example.com (including subdomains), inurl:admin,
    filetype:js (alias ext:js), mime:application/json, method:POST, status:403,
    type:javascript. Types: html, javascript, css, xml, json, network, forms, content, default.
    Combine predicates with AND; exclude with a leading minus and quote values containing spaces.
    Example: site:example.com filetype:js -inurl:vendor potential unsafe eval calls.
    Predicate-only queries work without an LLM, including in low-power mode.
    """

    return await _execute_search(ctx, search, scan_answer)


spider_results_instructions_found = "These resources were found by navigating a web server using links in the returned content."
spider_results_instructions_has_more = " This list isn't all of the results. Use the find_web_resources and find_urls tools to get more."
spider_results_instructions_not_found = "No resources were found by spidering the site. It may be there is no web server at the requested address and port."


def spider_instructions(results: List[HttpResource], has_more: bool) -> str:
    if results:
        instructions = spider_results_instructions_found
        if has_more:
            instructions += spider_results_instructions_has_more
    else:
        instructions = spider_results_instructions_not_found
    return instructions


class SpiderResults(BaseModel):
    url: str = Field(description="The starting URL of the spider")
    instructions: str = Field(default=spider_results_instructions_found)
    resources: List[HttpResource] = Field(description="The resources found by the spider")
    has_more: bool = Field(
        description="Whether the spider has more resources available that can be retrieved using the find_web_resources tool or listed by the find_urls tool")


async def is_spider_time_recent(server_ctx: ServerContext, url: str) -> Optional[float]:
    # TODO: consider the user_agent and headers, they may make a difference in the result
    max_age_seconds = 24 * 3600
    count_limit = 10
    try:
        qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client
        now = time.time()
        url_parsed = urlparse_ext(url)
        filters = qm.Filter(
            must=[
                qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
                qm.FieldCondition(key="meta.netloc", match=qm.MatchValue(value=url_parsed.netloc)),
            ]
        )
        logger.info("is_spider_time_recent using filters %s", repr(filters))
        latest_time: float = 0.0
        # count the number of urls to make sure it's not a one-off
        count = 0
        async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                     scroll_filter=filters):
            metadata = record.payload["meta"]
            try:
                ts = metadata.get("timestamp_float", 0.0)
                if now - ts > max_age_seconds:
                    continue

                if metadata.get("url", "").startswith(url):
                    if ts > latest_time:
                        latest_time = ts
                    count += 1
                    if count > count_limit:
                        # seems to be the results of a spider or busting
                        break
            except (ValueError, TypeError):
                pass
        logger.info(f"Spider check {url} found latest time {latest_time} and count {count}")
        seconds_since_spider = now - latest_time
        if seconds_since_spider < max_age_seconds and count > count_limit:
            logger.info(
                f"Spider for {url} was done {seconds_since_spider} seconds ago and found >= {count_limit} results")
            return True
        return False
    except Exception as e:
        logger.error("Failed checking for last spider time", exc_info=e)
        return False


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Spider Website",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True),
)
@progress_scope()
async def spider_website(
        ctx: Context,
        url: str,
        additional_hosts: AdditionalHostsField = None,
        user_agent: UserAgentField = None,
        request_headers: RequestHeadersField = None,
        cookies: CookiesField = None,
        timeout_seconds: Annotated[
            Optional[int],
            Field(120,
                description="How long to wait, in seconds, for responses before returning. Spidering will continue after returning.",
                ge=30, le=600,
            )
        ] = None,
) -> SpiderResults:
    """
    Spider the website at the url and index the results for further analysis. The find_web_resources
    tool can be used to continue the analysis. The find_hosts tool can be used to determine if
    a website has already been spidered.

    Invoke this tool when the user specifically asks to spider a URL or when the user wants to examine or analyze a site for which nothing has been indexed.

    Returns a list of resources found, including URL, response code, content type, and content length. All resources are indexed and can be queried using the find_web_resources tool. Content can be returned using the returned URL and the fetch_web_resource_content tool.
    """

    # coerce types
    additional_hosts = coerce_to_dict(additional_hosts)
    cookies = coerce_to_dict(cookies, '=', ';')
    request_headers = coerce_to_dict(request_headers, ':', '\n')

    rate_limit_requests_per_second = get_rate_limit_requests_per_second(url)
    request_headers = get_additional_http_headers(ctx, request_headers)

    await log_tool_history(ctx, "spider_website", url=url, additional_hosts=additional_hosts, user_agent=user_agent,
                           request_headers=request_headers,
                           rate_limit_requests_per_second=rate_limit_requests_per_second)
    server_ctx = await get_server_context()
    assert server_ctx.open_world

    url = url.strip()
    if await is_spider_time_recent(server_ctx, url):
        logger.info(f"{url} has been recently spidered, returning saved results")
        resources = (await find_web_resources(ctx, url, 100)).resources
        return SpiderResults(
            url=url,
            instructions=spider_instructions(resources, len(resources) >= 100),
            resources=resources,
            has_more=False,
        )

    context_id = ctx.request_context.lifespan_context.app_context_id
    spider_queue: Queue = server_ctx.task_queue
    spider_result_queue: Queue = server_ctx.spider_result_queue
    spider_queue_item = SpiderQueueItem(
        context_id=context_id,
        uri=url,
        depth=3,
        user_agent=user_agent,
        request_headers=request_headers,
        cookies=cookies,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
        rate_limit_requests_per_second=rate_limit_requests_per_second,
    )
    await asyncio.to_thread(spider_queue.put, spider_queue_item)
    results: List[HttpResource] = []
    has_more = True
    time_limit = time.time() + min(600, max(30, timeout_seconds or 120))
    while time.time() < time_limit:
        try:
            result_item: SpiderResultItem = await asyncio.to_thread(
                spider_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
            if result_item.context_id != context_id:
                if not result_item.is_expired():
                    spider_result_queue.put(result_item, block=False)
                    # wait so we don't get into a fast loop of putting back an item not for us
                    await asyncio.sleep(0.5)
                continue
        except (queue.Empty, TimeoutError):
            break
        http_resource = result_item.http_resource
        if http_resource is None:
            has_more = False
            break
        logger.debug(f"{http_resource} has been retrieved")
        results.append(http_resource)
        await report_progress(ctx, f"Found: {http_resource.url}")

    logger.info(f"spider_website for {url} returned {len(results)} results, has_more={has_more}")
    return SpiderResults(
        url=url,
        instructions=spider_instructions(results, has_more),
        resources=results,
        has_more=has_more,
    )
