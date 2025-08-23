import asyncio
import json
import logging
import queue
import time
from multiprocessing import Queue
from typing import List, Dict, Any, Optional, Annotated

import chromadb
from chromadb.api.models import AsyncCollection
from chromadb.errors import NotFoundError
from haystack import Document, Pipeline
from mcp import Resource, McpError
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation, CancelledElicitation
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, AnyUrl

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server import get_server_context, mcp_instance, log_tool_history, assert_elicitation, \
    ServerContext, get_additional_hosts, AdditionalHostsField, CookiesField, UserAgentField, RequestHeadersField
from shyhurricane.mcp_server.tools.find_indexed_metadata import find_netloc
from shyhurricane.target_info import parse_target_info, TargetInfo
from shyhurricane.task_queue import SpiderQueueItem
from shyhurricane.utils import HttpResource, urlparse_ext, documents_sort_unique, extract_domain, query_to_netloc, \
    munge_urls, filter_hosts_and_addresses

logger = logging.getLogger(__name__)


class RequestTargetUrl(BaseModel):
    data: str = Field(default="", description="URL(s), content types, technology of interest")


def _append_in_filter(conditions: List[Dict[str, Any]], field: str, values: List[str]):
    if len(values) == 1:
        conditions.append({"field": field, "operator": "==", "value": values[0]})
    elif len(values) > 1:
        conditions.append({"field": field, "operator": "in", "value": values})


def _documents_to_http_resources(documents: List[Document]) -> List[HttpResource]:
    https_resources = []
    for doc in documents:
        if doc.content and 'url' in doc.meta and 'type' in doc.meta:
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
find_web_resources_instructions_not_found = "No indexed resources were found using the query. Use the spider_website, directory_buster or index_http_url tools to populate the index."
find_web_resources_instructions_need_target = "Include a target URL, IP address or host name in query."
find_web_resources_instructions_low_power = "No indexed resources were considered due to low power mode. Include only host names, IP addresses or URLs in the query."


def find_web_resources_result(
        query: str,
        http_methods: Optional[List[str]],
        limit: int,
        results: List[HttpResource],
) -> FindWebResourcesResult:
    return FindWebResourcesResult(
        instructions=find_web_resources_instructions if results else find_web_resources_instructions_not_found,
        query=query,
        http_methods=http_methods,
        limit=limit,
        resources=results,
    )


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Find Web Resources",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_web_resources(
        ctx: Context,
        query: str,
        limit: Annotated[int, Field(100, description="Limit how many results are returned", ge=10, le=1000)] = 100,
        http_methods: Annotated[
            Optional[List[str]],
            Field(description="Limit results to requests made with the listed HTTP methods. If not specified all methods will be considered.")
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
    """
    await log_tool_history(ctx, "find_web_resources", query=query, limit=limit)
    server_ctx = await get_server_context()
    query = query.strip()
    limit = min(1000, max(10, limit or 100))
    logger.info("finding web resources for %s up to %d results", query, limit)

    if resources_by_url := await _find_web_resources_by_url(ctx, query, limit):
        return find_web_resources_result(results=resources_by_url, query=query, http_methods=http_methods, limit=limit)
    if resources_by_netloc := await _find_web_resources_by_netloc(ctx, query, limit):
        return find_web_resources_result(results=resources_by_netloc, query=query, http_methods=http_methods,
                                         limit=limit)
    if resources_by_hostname := await _find_web_resources_by_hostname(ctx, query, limit):
        return find_web_resources_result(results=resources_by_hostname, query=query, http_methods=http_methods,
                                         limit=limit)

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

    doc_types: list[str] = []
    targets: list[str] = []
    methods: list[str] = http_methods or []
    response_codes: list[str] = []

    async def determine_targets(target_query: str):
        await ctx.info("Determining target(s)")
        target_result = \
            website_context_pipeline.run({'builder': {'query': target_query}}).get('llm', {}).get('replies', [""])[0]
        if target_result:
            logger.info("Target result: %s", json.dumps(target_result))
            try:
                target_json = json.loads(target_result)
                targets.extend(target_json.get('target', []))
                doc_types.extend(target_json.get('content', []))
                # methods.extend(target_json.get('methods', [])) # may be too limiting, or maybe ignore for certain doc types
                response_codes.extend(target_json.get('response_codes', []))
            except json.decoder.JSONDecodeError:
                pass

    await determine_targets(query)

    if not targets:
        if recommended_urls := await _find_recommended_urls(ctx):
            targets.extend(recommended_urls)

    if not targets:
        try:
            logger.info("Asking user for URL(s)")
            assert_elicitation(server_ctx)
            target_elicit_result = await ctx.elicit(
                message="What URL(s) should we look for?", schema=RequestTargetUrl
            )
            match target_elicit_result:
                case AcceptedElicitation(data=data):
                    if data.data:
                        logger.info("User provided answer for URL request")
                        await determine_targets(data.data)
        except McpError:
            logger.info("elicit not supported, returning")
        finally:
            if not targets:
                return FindWebResourcesResult(
                    instructions=find_web_resources_instructions_need_target,
                    query=query,
                    http_methods=http_methods,
                    limit=limit,
                )

    parsed_targets: List[TargetInfo] = []
    for target in targets:
        try:
            parsed_targets.append(parse_target_info(target))
        except ValueError:
            pass
    filter_netloc = list(map(lambda t: t.netloc, parsed_targets))
    filter_domain = set()

    # check if we have data
    missing_netloc = set(filter_netloc.copy())
    for known_netloc in (await find_netloc(ctx, "")).network_locations:
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
    if missing_targets:
        missing_targets_str = ", ".join(map(str, missing_targets))

        if not server_ctx.open_world:
            return FindWebResourcesResult(
                instructions=find_web_resources_instructions_not_found,
                query=query,
                http_methods=http_methods,
                limit=limit,
            )

        logger.info(f"Asking user to spider {missing_targets_str}")
        try:
            assert_elicitation(server_ctx)
            spider_elicit_result = await ctx.elicit(
                message=f"There is no data for {missing_targets_str}. Would you like to start a scan?",
                schema=RequestTargetUrl
            )
            match spider_elicit_result:
                case AcceptedElicitation():
                    for target in missing_targets:
                        await spider_website(ctx, target.to_url())
                case DeclinedElicitation(), CancelledElicitation():
                    return FindWebResourcesResult(
                        instructions=find_web_resources_instructions_not_found,
                        query=query,
                        http_methods=http_methods,
                        limit=limit,
                    )
        except McpError:
            await ctx.info(f"Spidering {missing_targets_str}")
            logger.warning("elicit not supported, starting spider")
            for target in missing_targets:
                await spider_website(ctx, target.to_url())

    conditions = [
        {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION}
    ]
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

    logger.info(f"Searching for {', '.join(targets)} with filter {json.dumps(filters)}")
    await ctx.info(f"Searching for {', '.join(targets)}")

    loop = asyncio.get_running_loop()

    def progress_callback(message: str):
        try:
            asyncio.run_coroutine_threadsafe(ctx.info(message), loop).result()
        except Exception as e:
            logger.warning(f"Error reporting progress: {e}")

    res = await asyncio.to_thread(document_pipeline.run,
                                  data={"query": {"text": query, "filters": filters, "max_results": limit,
                                                  "progress_callback": progress_callback}},
                                  include_outputs_from={"combine"})

    documents = documents_sort_unique(res.get("combine", {}).get("documents", []), limit)

    return find_web_resources_result(results=_documents_to_http_resources(documents), query=query,
                                     http_methods=http_methods, limit=limit)


class SpiderConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm spider?", default=True)


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
        chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
        collection: AsyncCollection = await chroma_client.get_collection("network")
        now = time.time()
        url_parsed = urlparse_ext(url)
        where_filter = {"$and": [{"version": WEB_RESOURCE_VERSION}, {"netloc": url_parsed.netloc}]}
        logger.info("is_spider_time_recent using filters %s", json.dumps(where_filter))
        get_result = await collection.get(
            where=where_filter,
            include=["metadatas"])
        latest_time: float = 0.0
        # count the number of urls to make sure it's not a one-off
        count = 0
        for metadata in get_result.get("metadatas", []):
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
    except NotFoundError:
        # new database
        return False
    except Exception as e:
        logger.error("Failed checking for last spider time", exc_info=e)
        return False


@mcp_instance.tool(
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

    Returns a list of resources found, including URL, response code, content type, and content length. Indexes each URL that can be queried using the find_web_resources tool. URL content can be returned using the fetch_web_resource_content tool.
    """
    await log_tool_history(ctx, "spider_website", url=url, additional_hosts=additional_hosts, user_agent=user_agent,
                           request_headers=request_headers)
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
        except (queue.Empty, TimeoutError):
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
        url=url,
        instructions=spider_instructions(results, has_more),
        resources=results,
        has_more=has_more,
    )
