"""Read immutable saved pages without repeating their producing operation."""

import asyncio
from typing import Annotated, Literal, Union

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError

from shyhurricane import result_pages
from shyhurricane.mcp_server import mcp_instance
from shyhurricane.mcp_server.tools.application_graph import GraphResult
from shyhurricane.mcp_server.tools.deobfuscate_javascript import DeobfuscationResult
from shyhurricane.mcp_server.tools.directory_buster import DirBusterResults
from shyhurricane.mcp_server.tools.find_indexed_metadata import (
    FindDomainsResult,
    FindHostsResult,
    FindNetworkLocationResult,
    FindURLsResult,
)
from shyhurricane.mcp_server.tools.find_web_resources import FindWebResourcesResult, SpiderResults
from shyhurricane.mcp_server.tools.find_wordlists import FindWordlistsResult
from shyhurricane.mcp_server.tools.findings import QueryFindingsResult
from shyhurricane.mcp_server.tools.investigation import InvestigationResult
from shyhurricane.mcp_server.tools.port_scan import PortScanToolResult
from shyhurricane.result_pages import SavedTextResult
from shyhurricane.utils import HttpResource


class FindDomainsPage(BaseModel):
    source_tool: Literal["find_domains"]
    result: FindDomainsResult


class FindHostsPage(BaseModel):
    source_tool: Literal["find_hosts"]
    result: FindHostsResult


class FindNetlocPage(BaseModel):
    source_tool: Literal["find_netloc"]
    result: FindNetworkLocationResult


class FindUrlsPage(BaseModel):
    source_tool: Literal["find_urls"]
    result: FindURLsResult


class QueryFindingsPage(BaseModel):
    source_tool: Literal["query_findings"]
    result: QueryFindingsResult


class InvestigationPage(BaseModel):
    source_tool: Literal["find_investigation_targets"]
    result: InvestigationResult


class FindWordlistsPage(BaseModel):
    source_tool: Literal["find_wordlists"]
    result: FindWordlistsResult


class FindWebResourcesPage(BaseModel):
    source_tool: Literal["find_web_resources"]
    result: FindWebResourcesResult


class SpiderWebsitePage(BaseModel):
    source_tool: Literal["spider_website"]
    result: SpiderResults


class DirectoryBusterPage(BaseModel):
    source_tool: Literal["directory_buster"]
    result: DirBusterResults


class PortScanPage(BaseModel):
    source_tool: Literal["port_scan"]
    result: PortScanToolResult


class IndexHttpUrlPage(BaseModel):
    source_tool: Literal["index_http_url"]
    result: HttpResource


class DeobfuscateJavascriptPage(BaseModel):
    source_tool: Literal["deobfuscate_javascript"]
    result: DeobfuscationResult


class PortScanXmlPage(BaseModel):
    source_tool: Literal["port_scan_xml"]
    result: SavedTextResult


class ApplicationGraphPage(BaseModel):
    source_tool: Literal[
        "continue_application_graph_query",
        "find_application_endpoints",
        "find_application_elements",
        "find_application_relationships",
        "trace_application_data_flow",
        "find_user_journey_paths",
    ]
    result: GraphResult


ResultPageValue = Annotated[
    Union[
        FindDomainsPage,
        FindHostsPage,
        FindNetlocPage,
        FindUrlsPage,
        QueryFindingsPage,
        InvestigationPage,
        FindWordlistsPage,
        FindWebResourcesPage,
        SpiderWebsitePage,
        DirectoryBusterPage,
        PortScanPage,
        IndexHttpUrlPage,
        DeobfuscateJavascriptPage,
        PortScanXmlPage,
        ApplicationGraphPage,
    ],
    Field(discriminator="source_tool"),
]


class ResultPage(RootModel[ResultPageValue]):
    """Publish the discriminated object directly, without the SDK's union wrapper."""

    model_config = ConfigDict(json_schema_extra={"type": "object"})

    @property
    def source_tool(self) -> str:
        return self.root.source_tool

    @property
    def result(self):
        return self.root.result


@mcp_instance.tool(
    annotations=ToolAnnotations(title="Get Saved Result Page", read_only_hint=True, open_world_hint=False),
)
async def get_result_page(ctx: Context, page_token: str) -> ResultPage:
    """Read a saved page using a next/previous token or an XML page token.

    Call get_result_page with pagination.next_page_token, pagination.previous_page_token
    or nmap_xml_page_token.
    Returns {source_tool, result}; result uses the original tool schema. Further navigation tokens
    are in result.pagination. A null next_page_token means there are no additional saved pages.
    Pages are fixed snapshots and do not wait for new discoveries.
    Tokens are private bearer capabilities and expire at expires_at.
    XML pages contain fragments in result.text; concatenate them in page order.
    Repeat the original operation only if the saved result is expired, missing or corrupt.
    """
    store = await result_pages.get_result_store()
    saved = await asyncio.to_thread(store.read, page_token)
    try:
        return ResultPage.model_validate(saved)
    except ValidationError as error:
        raise ToolError("Saved result is corrupt. Repeat the original operation.") from error
