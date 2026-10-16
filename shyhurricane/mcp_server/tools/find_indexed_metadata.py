import logging
from inspect import unwrap
from typing import Annotated, Any, List, Optional, TypeAlias

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from openai import BaseModel
from pydantic import Field
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm

from shyhurricane.db import scroll_qdrant_collection
from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.indexing_wait import IndexingStatus, indexed_inventory
from shyhurricane.mcp_server import get_server_context, log_tool_history, mcp_instance
from shyhurricane.result_pages import Pagination, paged_results
from shyhurricane.utils import query_to_netloc

logger = logging.getLogger(__name__)

finder_instructions_found = (
    "These are indexed {0}. Read additional saved results with "
    "get_result_page(pagination.next_page_token), when present. "
    "A null next_page_token means there are no additional saved pages. "
    "Use find_web_resources to search their indexed resources within the existing scope."
)
finder_instructions_not_found = (
    "No indexed {0} matched this filter. Check or broaden the filter within the existing scope first. "
    "An empty match does not establish that the target has no indexed data. If the target has no "
    "indexed data, use available indexing tools only within the user-authorized scope."
)


def _finder_instructions(subject: str, results: Any) -> str:
    if results:
        return finder_instructions_found.format(subject)
    else:
        return finder_instructions_not_found.format(subject)


class FindDomainsResult(BaseModel):
    indexing: IndexingStatus | None = None
    pagination: Pagination | None = None
    instructions: str = Field(description="Instructions for interpreting the results")
    query: Optional[str] = Field(description="The query used to these find domains")
    domains: List[str] = Field(description="The domains that have been indexed")

DomainQueryField: TypeAlias = Annotated[str,
    Field(description="""Limit the results using the "ends with" operator on the domain""")
]

@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Indexed Domains",
        read_only_hint=True,
        open_world_hint=False),
)
@paged_results("domains")
@indexed_inventory(domains=True)
async def find_domains(
        ctx: Context,
        query: Annotated[
            Optional[str],
            Field(description="Limit the results using a \"contains\" operator, if empty return all domains")
        ] = None,
        limit: Annotated[int, Field(100, ge=1, le=1000, description="Results per page")] = 100
) -> FindDomainsResult:
    """List domains with indexed web resources.

    Query indexed resources for a list of domains that have resources that can be researched.

    Use get_result_page(pagination.next_page_token) for additional saved results.
    A null next_page_token means there are no additional saved pages.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.
    """
    await log_tool_history(ctx, "find_domains", query=query)
    server_ctx = await get_server_context()
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client
    result = set()
    original_query = query
    query, port = query_to_netloc(query)
    filters = qm.Filter(
        must=[
            qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
        ]
    )
    async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                 scroll_filter=filters):
        metadata = record.payload["meta"]
        if "domain" in metadata:
            domain = metadata["domain"].lower()
            if domain and (not query or query.lower() in domain):
                result.add(domain)
    return FindDomainsResult(
        instructions=_finder_instructions("domains", result),
        query=original_query,
        domains=sorted(list(result)),
    )


class FindHostsResult(BaseModel):
    indexing: IndexingStatus | None = None
    pagination: Pagination | None = None
    instructions: str = Field(description="Instructions for interpreting the results")
    domain_query: str = Field(description="The query used to these find hosts")
    hosts: List[str] = Field(description="The hosts that have been indexed")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Indexed Hostnames",
        read_only_hint=True,
        open_world_hint=False),
)
@paged_results("hosts")
@indexed_inventory(domains=False)
async def find_hosts(
        ctx: Context,
        domain_query: DomainQueryField,
        limit: Annotated[int, Field(100, ge=1, le=1000, description="Results per page")] = 100
) -> FindHostsResult:
    """List indexed hosts for a domain.

    Query indexed resources for a list of hosts for the given domain.

    Use get_result_page(pagination.next_page_token) for additional saved results.
    A null next_page_token means there are no additional saved pages.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.
    """
    await log_tool_history(ctx, "find_hosts", domain_query=domain_query)
    server_ctx = await get_server_context()
    try:
        qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client
        result = set()
        original_query = domain_query
        domain_query, port = query_to_netloc(domain_query)
        filters = qm.Filter(
            must=[
                qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
            ]
        )
        async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                     scroll_filter=filters):
            metadata = record.payload["meta"]
            if "host" in metadata:
                hostname = metadata["host"].lower()
                if not domain_query or hostname.endswith(domain_query):
                    if port is None or port <= 0 or (metadata.get('port', None) == port):
                        result.add(hostname)
        return FindHostsResult(
            instructions=_finder_instructions("hosts", result),
            domain_query=original_query,
            hosts=sorted(list(result)),
        )
    except Exception as e:
        logger.error("find_hosts error: %s", domain_query, exc_info=e)
        raise e


class FindNetworkLocationResult(BaseModel):
    indexing: IndexingStatus | None = None
    pagination: Pagination | None = None
    instructions: str = Field(description="Instructions for interpreting the results")
    domain_query: str = Field(description="The query used to these find network locations (host:port)")
    network_locations: List[str] = Field(description="The network locations that have been indexed")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Indexed Network Locations (host:port)",
        read_only_hint=True,
        open_world_hint=False),
)
@paged_results("network_locations")
@indexed_inventory(domains=False)
async def find_netloc(
        ctx: Context,
        domain_query: DomainQueryField,
        limit: Annotated[int, Field(100, ge=1, le=1000, description="Results per page")] = 100
) -> FindNetworkLocationResult:
    """List indexed network locations (host:port) for a domain.

    Query indexed resources for a list of network locations, i.e. host:port, for a given domain.

    Use get_result_page(pagination.next_page_token) for additional saved results.
    A null next_page_token means there are no additional saved pages.

    Invoke this tool when the user asks about websites that have been scanned, spidered or indexed.
    """
    await log_tool_history(ctx, "find_netloc", domain_query=domain_query)
    server_ctx = await get_server_context()
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client
    result = set()
    original_query = domain_query
    domain_query, port = query_to_netloc(domain_query)
    filters = qm.Filter(
        must=[
            qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
        ]
    )
    async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                 scroll_filter=filters):
        metadata = record.payload["meta"]
        if "host" in metadata:
            hostname = metadata['host'].lower()
            if not domain_query or hostname.endswith(domain_query):
                if port is None or port <= 0 or (metadata.get('port', -1) == port):
                    result.add(metadata.get('netloc', hostname).lower())
    return FindNetworkLocationResult(
        instructions=_finder_instructions("network locations (host:port)", result),
        domain_query=original_query,
        network_locations=sorted(list(result)),
    )


class FindURLsResult(BaseModel):
    indexing: IndexingStatus | None = None
    pagination: Pagination | None = None
    instructions: str = Field(description="Instructions for interpreting the results")
    host_query: str = Field(description="The query used to these find URLs by host")
    path_query: Optional[str] = Field(description="The query used to these find URLs by path")
    limit: int = Field(description="The maximum number of URLs to return")
    urls: List[str] = Field(description="The URLs that have been indexed")


# TODO: add a parameter for URLs to skip
@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Indexed URLs",
        read_only_hint=True,
        open_world_hint=False),
)
@paged_results("urls")
@indexed_inventory(domains=False)
async def find_urls(
        ctx: Context,
        host_query: Annotated[str, Field(description="Limit the results using the \"ends with\" operator")],
        path_query: Annotated[Optional[str], Field(description="If specified, match URLs using a \"contains\" operator.")] = None,
        limit: Annotated[int, Field(100, description="Results per page", ge=1, le=1000)] = 100
) -> FindURLsResult:
    """List indexed URLs for a host or domain.

    Query indexed resources for a list of URLs for the given host or domain.

    Use get_result_page(pagination.next_page_token) for additional saved results.
    A null next_page_token means there are no additional saved pages.

    Invoke this tool when the user asks for page URLs that have been scanned, spidered or indexed.

    Invoke this tool when a list of URLs for a website is needed for analysis.
    """
    await log_tool_history(ctx, "find_urls", host_query=host_query, limit=limit)
    server_ctx = await get_server_context()
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client
    result = set()
    original_host_query = host_query
    host_query, port = query_to_netloc(host_query)
    filters = qm.Filter(
        must=[
            qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
        ]
    )
    async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                 scroll_filter=filters):
        metadata = record.payload["meta"]
        if "host" in metadata and "url" in metadata:
            hostname = metadata['host'].lower()
            if not host_query or hostname.endswith(host_query):
                if port is None or port <= 0 or (metadata.get('port', None) == port):
                    url = metadata['url']
                    if not path_query or path_query in url:
                        result.add(url)
    return FindURLsResult(
        instructions=_finder_instructions("URLs", result),
        host_query=original_host_query,
        path_query=path_query,
        limit=limit,
        urls=sorted(list(result)),
    )


async def find_netloc_all(ctx: Context, domain_query: str) -> FindNetworkLocationResult:
    """Load the complete inventory for internal target selection without creating pages."""
    return await unwrap(find_netloc)(ctx, domain_query)
