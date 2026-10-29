"""Read saved investigation targets without starting analysis or contacting applications."""

import asyncio
from contextlib import closing
from typing import Annotated

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shyhurricane.finding_metadata import VULNERABILITY_TYPES
from shyhurricane.graph.query import scope_predicate
from shyhurricane.investigation.storage import CorrelationStore
from shyhurricane.mcp_server import get_server_context, log_tool_history, mcp_instance
from shyhurricane.mcp_server.progress import progress_scope, report_progress
from shyhurricane.mcp_server.tools.application_graph import Scope
from shyhurricane.result_pages import Pagination, paged_results


class InvestigationResult(BaseModel):
    results: list[dict] = Field(default_factory=list)
    findings: dict = Field(default_factory=dict)
    category_coverage: dict = Field(default_factory=dict)
    status: dict = Field(default_factory=dict)
    graph_revision: int = 0
    policy_version: int = 1
    retrieval_truncated: bool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    analysis_gaps: list[str] = Field(default_factory=list)
    pagination: Pagination | None = None
    instructions: str = (
        "Complete status means processing completed, not complete evidence or verification. "
        "Priority scores rank investigation work, not exploit probability. Review witnesses and evidence IDs. "
        "Materialization runs asynchronously; pending, stale, failed, or bounded results are incomplete. "
        "Navigation/protection hypotheses do not establish exploit composition or session continuity. "
        "Use scoped graph discovery when results are pending. Do not automatically save these candidates as findings."
    )


@mcp_instance.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
@progress_scope()
@paged_results("results")
async def find_investigation_targets(
    ctx: Context,
    scope: Scope,
    vulnerability_type: Annotated[
        str | None, Field(description=("Optional normalized category: " + ", ".join(VULNERABILITY_TYPES)))
    ] = None,
    include_hypotheses: bool = True,
    limit: Annotated[int, Field(ge=1, le=1000)] = 20,
) -> InvestigationResult:
    """Read background-ranked finding/graph correlations, shared hotspots, and possible chains.

    Use after scoped query_findings, then inspect suggested focused evidence calls.
    All fields are captured evidence or deterministic rules; this tool never invokes a model or target.
    Follow pagination.next_page_token with get_result_page. A complete saved page set does not
    establish assessment completeness. Unknown metadata remains unknown.
    """
    try:
        scope_predicate(scope)
        if vulnerability_type is not None and vulnerability_type not in VULNERABILITY_TYPES:
            raise ValueError("Unsupported vulnerability_type; use a documented normalized category")
    except ValueError as error:
        raise ToolError(str(error)) from error
    await log_tool_history(
        ctx,
        "find_investigation_targets",
        scope=scope,
        vulnerability_type=vulnerability_type,
        include_hypotheses=include_hypotheses,
    )
    server = await get_server_context()
    await report_progress(ctx, "Reading saved investigation targets")

    def read():
        with closing(CorrelationStore(server.db)) as store:
            return store.read(scope, vulnerability_type, include_hypotheses)

    result = await asyncio.to_thread(read)
    await report_progress(ctx, f"Loaded {len(result['results'])} saved investigation targets")
    return InvestigationResult(**result)
