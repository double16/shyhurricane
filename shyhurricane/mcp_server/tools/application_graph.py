"""Closed-world relationship and data-flow tools over captured application artifacts."""

import logging
from typing import Annotated, Literal

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, BeforeValidator, Field

from shyhurricane.graph.query import scope_predicate
from shyhurricane.indexing_wait import IndexingStatus, indexing_scope, wait_for_indexing
from shyhurricane.mcp_server import get_server_context, log_tool_history, mcp_instance
from shyhurricane.mcp_server.graph_execution import execute_graph
from shyhurricane.result_pages import Pagination, paged_results

logger = logging.getLogger(__name__)


def trim_input(value):
    """Remove incidental boundary whitespace without coercing invalid input types."""
    return value.strip() if isinstance(value, str) else value


TrimmedString = Annotated[str, BeforeValidator(trim_input)]

Scope = Annotated[
    TrimmedString,
    Field(
        description="Application scope: hostname, host:port, or HTTP(S) URL prefix. "
        "Hostname scopes include subdomains; URL scopes restrict scheme, host, and path prefix. "
        "Surrounding whitespace is trimmed from all graph string arguments and kinds entries."
    ),
]
Historical = Annotated[
    bool, Field(description="Include all retained capture versions when true; default false selects latest versions.")
]
AsOf = Annotated[
    float | None,
    Field(
        description="Capture-time cutoff as Unix seconds (not milliseconds). Null means no cutoff. "
        "With historical=false, select the latest captures at or before this time."
    ),
]
PageSize = Annotated[
    int,
    Field(
        ge=1,
        le=1000,
        description="Results per saved page, from 1 to 1000; default 20. "
        "Use pagination.next_page_token with get_result_page for more pages.",
    ),
]
Depth = Annotated[
    int, Field(ge=1, le=32, description="Maximum relationship steps to traverse, from 1 to 32; default 8.")
]
Direction = Annotated[
    Literal["forward", "backward"],
    BeforeValidator(trim_input),
    Field(
        description="Traversal direction: forward follows outgoing relationships; backward follows incoming "
        "relationships. For flow traces, forward seeks sinks and backward seeks sources "
        "when end is omitted. Default forward."
    ),
]
ElementId = Annotated[
    TrimmedString,
    Field(
        description="Element ID from find_application_elements results[].id, resource ID from "
        "find_application_endpoints results[].id, or exact captured resource URL; "
        "use the same application scope. Pass opaque IDs unchanged."
    ),
]
JourneyEndpoint = Annotated[
    TrimmedString,
    Field(
        description="Exact captured resource URL or opaque resource ID from find_application_elements "
        "results[].id filtered to resource kinds, or find_application_endpoints results[].id. "
        "Use the same application scope."
    ),
]


Detail = Annotated[
    Literal["compact", "full"],
    BeforeValidator(trim_input),
    Field(
        description="Result detail: compact (default) keeps IDs, roles, URLs, locations and evidence references; "
        "full includes all public graph properties. Selection and traversal are unchanged."
    ),
]
ExactUrl = Annotated[
    TrimmedString | None,
    Field(description="Exact resource URL filter, not a prefix or text search. Null applies no URL filter."),
]


class GraphResult(BaseModel):
    indexing: IndexingStatus | None = None
    results: list[dict]
    analysis_gaps: list[str] = Field(default_factory=list)
    analysis_summaries: list[dict] = Field(default_factory=list)
    instructions: str
    retrieval_truncated: bool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    pagination: Pagination | None = None
    resolved_start_ids: list[str] = Field(default_factory=list, description="Up to 20 resolved flow start seed IDs")
    resolved_end_ids: list[str] = Field(default_factory=list, description="Up to 20 resolved flow destination seed IDs")
    resolved_start_count: int = Field(0, description="Total selected flow start seeds before traversal")
    resolved_end_count: int = Field(0, description="Total selected flow destination seeds before traversal")
    seed_ids_limited: bool = Field(False, description="True if resolved seed ID examples omit selected seeds")


@indexing_scope()
async def query(ctx, tool, operation, scope, **arguments):
    scope = trim_input(scope)
    arguments = {
        key: [trim_input(item) for item in value] if isinstance(value, list) else trim_input(value)
        for key, value in arguments.items()
    }
    await log_tool_history(ctx, tool, scope=scope, **arguments)
    server = await get_server_context()
    if server.graph_store is None:
        raise ToolError("Application graph is unavailable")
    try:
        matches = scope_predicate(scope)
        indexing = await wait_for_indexing(ctx, server, matches, graph=True)
        result = await execute_graph(ctx, server.graph_store, operation, scope, **arguments)
        if result is not None:
            return {**result, "indexing": indexing.model_dump()}
        return {"indexing": indexing.model_dump()} if indexing.potentially_incomplete else None
    except ValueError as error:
        raise ToolError(str(error)) from error
    except Exception as error:
        logger.exception("Application graph query failed: tool=%s operation=%s scope=%s", tool, operation, scope)
        raise ToolError("Application graph query failed; inspect Neo4j health and ingest backlog") from error


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@paged_results("results")
async def find_application_endpoints(
    ctx: Context,
    scope: Scope,
    url: ExactUrl = None,
    method: Annotated[
        TrimmedString | None,
        Field(description="Exact HTTP method filter, ignoring case, such as GET or POST. Null includes all methods."),
    ] = None,
    historical: Historical = False,
    as_of: AsOf = None,
    limit: Annotated[
        int,
        Field(
            ge=1,
            le=1000,
            description="Endpoint records per saved page, 1–1000; default 5. "
            "Use pagination.next_page_token with get_result_page for more.",
        ),
    ] = 5,
    detail: Annotated[
        Literal["inventory", "summary"],
        BeforeValidator(trim_input),
        Field(description="inventory (default): fast own-URL discovery with IDs, methods and capture status. "
              "summary: inputs/scripts/source/sink associations; supply an exact url and method when known. "
              "Use summary directly for a known endpoint when rich details are needed."),
    ] = "inventory",
) -> GraphResult:
    """Discover endpoints with inventory; enrich selected exact URLs with summary.

    Start domain/host enumeration with detail="inventory" and follow saved pages for more.
    Inventory includes own-URL matches, including assets, and omits uncomputed association counts.
    For inputs, forms, scripts and source/sink associations use detail="summary" with an exact url
    and method when known. A known endpoint needing details can go directly to summary.
    Avoid broad summaries during reconnaissance. Summary examples are bounded, not complete.
    Inspect truncation, indexing, analysis gaps and unknown capture status before drawing conclusions.
    External dependencies need focused relationship discovery; inventory does not enumerate them.
    Script association is not flow evidence. Neither mode infers business operations.

    Examples: find_application_endpoints(scope="taxact.com", detail="inventory");
    find_application_endpoints(scope="taxact.com", url="https://tst.taxact.com/authuimw/v1/time",
    method="GET", detail="summary"). Other graph tools use compact/full, not inventory/summary.
    """
    return GraphResult(
        **await query(
            ctx,
            "find_application_endpoints",
            "endpoints",
            scope,
            url=url,
            method=method,
            historical=historical,
            as_of=as_of,
            detail=detail,
        )
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@paged_results("results")
async def find_application_elements(
    ctx: Context,
    scope: Scope,
    kinds: Annotated[
        list[TrimmedString] | None,
        Field(
            description="Filter by case-sensitive element kind strings, matching any listed kind; "
            "examples: resource, element, field, cookie, origin. Omitted, null, or [] means "
            "all kinds. Discover other values in results[].kind."
        ),
    ] = None,
    role: Annotated[
        Literal["source", "sink"] | None,
        BeforeValidator(trim_input),
        Field(
            description="Filter by static data-flow role: source reads input, sink consumes data. "
            "Omitted or null includes all roles; classifications are investigation candidates."
        ),
    ] = None,
    url: Annotated[
        TrimmedString | None,
        Field(
            description="Exact element resource URL filter, not a prefix or text search. "
            "Omitted or null applies no URL filter."
        ),
    ] = None,
    context_url: Annotated[
        TrimmedString | None,
        Field(
            description="Exact page URL: match elements at that URL or with that consuming-document context. "
            "Includes associated external scripts; null applies no context filter."
        ),
    ] = None,
    historical: Historical = False,
    as_of: AsOf = None,
    limit: PageSize = 20,
    detail: Detail = "compact",
) -> GraphResult:
    """Find captured resources, elements, sources, and sinks without target requests.

    Begin with find_application_endpoints for URL/method summaries. Use kinds=["resource"] for
    resource-only discovery, or context_url plus role for page-associated flow candidates.
    scope is a hostname, host:port, or HTTP(S) URL prefix. as_of is a Unix capture timestamp.
    historical includes retained versions. Use returned IDs for flow/relationship queries.
    Use get_result_page for saved pages. Missing results do not prove absence.
    """
    return GraphResult(
        **await query(
            ctx,
            "find_application_elements",
            "elements",
            scope,
            kinds=kinds,
            role=role,
            url=url,
            context_url=context_url,
            detail=detail,
            historical=historical,
            as_of=as_of,
        )
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@paged_results("results")
async def find_application_relationships(
    ctx: Context,
    scope: Scope,
    element_id: ElementId,
    direction: Direction = "forward",
    kinds: Annotated[
        list[TrimmedString] | None,
        Field(
            description="Filter by case-sensitive relationship kind strings, matching any listed kind; "
            "examples: CONTAINS, LOADS, NAVIGATES_TO, SUBMITS_TO, FLOWS_TO. Omitted, null, "
            "or [] means all kinds. Discover values in results[].steps[].kind."
        ),
    ] = None,
    max_depth: Annotated[
        int, Field(ge=1, le=3, description="Maximum relationship steps to inspect, from 1 to 3; default 1.")
    ] = 1,
    historical: Historical = False,
    as_of: AsOf = None,
    limit: PageSize = 20,
    detail: Detail = "compact",
) -> GraphResult:
    """Inspect incoming/outgoing relationships with evidence IDs. Never fetches target content.

    Use IDs from find_application_elements or find_application_endpoints, or an exact resource URL.
    Use get_result_page for additional saved results. Compact detail is the default.
    """
    return GraphResult(
        **await query(
            ctx,
            "find_application_relationships",
            "paths",
            scope,
            start=element_id,
            detail=detail,
            direction=direction,
            kinds=kinds,
            max_depth=max_depth,
            historical=historical,
            as_of=as_of,
        )
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@paged_results("results")
async def trace_application_data_flow(
    ctx: Context,
    scope: Scope,
    start: ElementId,
    end: Annotated[
        TrimmedString | None,
        Field(
            description="Optional destination element ID from find_application_elements results[].id, "
            "resource ID from find_application_endpoints results[].id, or exact resource URL in the same scope. "
            "Resources select associated sinks forward or sources backward. Null searches for sinks forward, sources "
            "when backward. Pass opaque IDs unchanged."
        ),
    ] = None,
    direction: Direction = "forward",
    max_depth: Depth = 8,
    historical: Historical = False,
    as_of: AsOf = None,
    limit: PageSize = 20,
    detail: Detail = "compact",
) -> GraphResult:
    """Trace possible static data flow from an element ID to sources/sinks or an optional end ID.

    Get IDs from find_application_elements or find_application_endpoints results[].id, or use exact
    resource URLs. Resource starts select associated sources forward or sinks backward; resource ends
    select the opposite role. Inspect resolved_start_ids/resolved_end_ids. Association is not a flow
    edge: only existing flow relationships appear in paths. Compact detail is the default.
    Missing modules and dynamic dispatch can make results incomplete. This is not runtime proof.
    """
    return GraphResult(
        **await query(
            ctx,
            "trace_application_data_flow",
            "paths",
            scope,
            start=start,
            detail=detail,
            end=end,
            direction=direction,
            mode="flow",
            max_depth=max_depth,
            historical=historical,
            as_of=as_of,
        )
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@paged_results("results")
async def find_user_journey_paths(
    ctx: Context,
    scope: Scope,
    start: JourneyEndpoint,
    end: JourneyEndpoint,
    max_depth: Depth = 8,
    historical: Historical = False,
    as_of: AsOf = None,
    limit: PageSize = 20,
    detail: Detail = "compact",
) -> GraphResult:
    """Find possible navigation/form/redirect paths between exact URLs or resource IDs.

    Get resource IDs from find_application_elements results[].id with kinds=["resource"].
    Captures lack browser-session identity: these are possible journeys, not recorded user sessions.
    Assets and origin-only Referer associations do not establish navigation. No target requests occur.
    """
    return GraphResult(
        **await query(
            ctx,
            "find_user_journey_paths",
            "paths",
            scope,
            start=start,
            detail=detail,
            end=end,
            mode="journey",
            max_depth=max_depth,
            historical=historical,
            as_of=as_of,
        )
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def fetch_application_graph_evidence(
    ctx: Context,
    evidence_id: Annotated[
        TrimmedString,
        Field(
            description="Opaque evidence ID from results[].steps[].evidence_id returned by "
            "find_application_relationships, trace_application_data_flow, or "
            "find_user_journey_paths. Pass the ID unchanged."
        ),
    ],
) -> dict | None:
    """Read evidence and source locations for a relationship; never contacts the application.

    Supply results[].steps[].evidence_id from find_application_relationships,
    trace_application_data_flow, or find_user_journey_paths. Reads published evidence directly
    without waiting for indexing; possession of its ID permits retrieval.
    """
    evidence_id = trim_input(evidence_id)
    await log_tool_history(ctx, "fetch_application_graph_evidence", evidence_id=evidence_id)
    server = await get_server_context()
    if server.graph_store is None:
        raise ToolError("Application graph is unavailable")
    try:
        return await execute_graph(ctx, server.graph_store, "evidence", evidence_id)
    except Exception as error:
        logger.exception(
            "Application graph query failed: tool=fetch_application_graph_evidence operation=evidence evidence_id=%s",
            evidence_id,
        )
        raise ToolError("Application graph query failed; inspect Neo4j health and ingest backlog") from error
