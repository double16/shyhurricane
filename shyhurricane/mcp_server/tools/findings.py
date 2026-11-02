import asyncio
import json
import logging
import math
from typing import Annotated, List, Optional

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from openai import BaseModel
from pydantic import Field, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from shyhurricane.finding_metadata import FindingMetadata, metadata_dict
from shyhurricane.finding_search import (
    FINDING_SEMANTIC_LIMIT,
    finding_ids,
    load_findings,
    parse_finding_query,
    rank_findings,
)
from shyhurricane.mcp_server import get_server_context, log_tool_history, mcp_instance
from shyhurricane.mcp_server.progress import progress_scope, report_progress
from shyhurricane.nuclei_findings import is_nuclei_finding, nuclei_finding_to_markdown
from shyhurricane.persistent_queue import get_persistent_queue
from shyhurricane.result_pages import Pagination, paged_results
from shyhurricane.target_info import parse_target_info
from shyhurricane.task_queue import SaveFindingQueueItem
from shyhurricane.task_queue.finding_worker import FINDING_VERSION

logger = logging.getLogger(__name__)


def enqueue_finding(db: str, item: SaveFindingQueueItem) -> None:
    """Commit a submission without resuming another worker's in-flight items."""
    queue = get_persistent_queue(db, "scan_finding_queue", auto_resume=False)
    try:
        queue.put(item)
    finally:
        queue.close()


finding_target_invalid_instructions = "Target must be a valid URL, hostname, IP address, host:port or ip:port. Retry with a corrected target."
finding_not_found_instructions = (
    "No saved findings matched this target. Check its format or review indexed evidence within the "
    "existing scope. Queued findings may not be searchable yet. An empty result does not establish "
    "that the target is secure."
)
finding_instructions = (
    "These are previously saved findings; do not save them again. They may be unverified or outdated. "
    "Review evidence and verification status before treating them as confirmed vulnerabilities. "
    "Use get_result_page(pagination.next_page_token) for additional saved findings. "
    "A null next_page_token means there are no additional saved pages."
)


class SaveFindingResult(BaseModel):
    instructions: str = Field(description="Instructions for processing the result")
    target: str = Field(description="Target of the finding")
    title: Optional[str] = Field(description="Title of the finding")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Save Finding",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False),
)
async def save_finding(
        ctx: Context,
        target: Annotated[str, Field(description="""
- Must be a URL, IP address, domain name, or hostname.
- Port numbers may be included using a colon suffix (e.g. `target.local:8080`).
""")],
        markdown: Annotated[str, Field(description="""
- The full body of the finding in **Markdown format**.
- Each finding must include all the following sections:
    - **Title** – A concise, descriptive heading.
    - **Issue Summary** – What is wrong and why it is important.
    - **Discovery Method** – How the issue was found (tool or technique used).
    - **Evidence** – Observed behavior and affected resource; redact sensitive values.
    - **Verification Status** – Confirmed, suspected, or unverified, with supporting limitations.
    - **Reproduction Steps** – Step-by-step instructions to reproduce the issue.
    - **PoC** – Exploit code, request sample, or screenshot (if applicable).
    - **Fix** – Recommended remediation or mitigation.
    - **References** – Relevant CVEs, OWASP links, research articles, etc.
""")],
        title: Annotated[
            Optional[str], Field(description="""A short, descriptive summary of the issue (one line max).""")],
        metadata: FindingMetadata | None = None,
) -> SaveFindingResult:
    """Save security finding associated with the current target.

    Save each new finding within the user's task and scope, recording observed evidence and
    verification status. Distinguish suspected issues from confirmed vulnerabilities.
    Do not invent evidence, reproduction steps or references; mark unavailable details explicitly.
    Do not re-save findings returned by query_findings.
    Saving is asynchronous: success means queued, and immediate queries may not include it.
    """
    await log_tool_history(ctx, "save_finding", target=target, finding_title=title, markdown=len(markdown))

    try:
        parse_target_info(target)
    except ValueError:
        return SaveFindingResult(
            instructions=finding_target_invalid_instructions,
            target=target,
            title=title,
        )

    server_ctx = await get_server_context()
    await asyncio.to_thread(enqueue_finding, server_ctx.db, SaveFindingQueueItem(
        target=target,
        markdown=markdown,
        title=title,
        metadata=metadata_dict(metadata),
    ))

    return SaveFindingResult(
        instructions="Finding is queued for saving; it may not be searchable immediately.",
        target=target,
        title=title,
    )


class Finding(BaseModel):
    finding_id: str = ""
    metadata_revision: int = 1
    metadata: dict = Field(default_factory=dict)
    metadata_conflicts: list[dict] = Field(default_factory=list)
    target: str = Field(description="Target of the finding")
    title: str = Field(description="Title of the finding")
    markdown: str = Field(description="Markdown of the finding")
    score: float | None = Field(None, description="Cosine similarity; not vulnerability confidence")


class QueryFindingsResult(BaseModel):
    query: str = Field(description="Complete finding-search expression")
    retrieval_truncated: bool = False
    pagination: Pagination | None = None
    instructions: str = Field(description="Instructions for processing the findings")
    limit: int = Field(description="Limit for the number of results")
    findings: List[Finding] = Field(default=[], description="Findings associated with the target")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Query for Findings",
        read_only_hint=True,
        open_world_hint=False),
)
@progress_scope()
@paged_results("findings")
async def query_findings(
        ctx: Context,
        query: Annotated[str, Field(description=(
            "Scoped search: site:example.com -ext:js authentication bypass. "
            "Use predicates only for exhaustive retrieval, or a standalone hostname, IP, host:port, or URL."
        ))],
        limit: Annotated[int, Field(10, ge=1, le=1000, description="Findings per page")] = 10,
        score_threshold: Annotated[float | None, Field(description=(
            "Optional minimum cosine similarity, -1 to 1. Ignored without semantic text."
        ))] = None,
) -> QueryFindingsResult:
    """Query previously saved findings for a target.

    Accept site:, inurl:, filetype:/ext:, quoted values, and - exclusions; combine with AND.
    Combine positive site: scope with optional natural-language text for semantic ranking.
    No mime:, method:, status:, or type: predicates. Predicate-only queries retrieve all scoped findings.
    Without semantic text, score_threshold is ignored, including range checks.
    Semantic searches save at most 1000 findings; narrow the search when this limit is reached.
    Semantic results are bounded; scores measure similarity, not vulnerability confidence.
    Plain root HTTP(S) URLs search hostname scope, retaining explicit ports. Other URLs use prefixes.
    Explicit site: URL scopes retain scheme and path. Hostname scopes include subdomains.
    Use focused semantic queries for vulnerability searches; use predicates only for exhaustive scoped retrieval.
    URL filters can omit host-level findings.

    Invoke this tool when the user asks for existing vulnerabilities or is looking for a direction for testing a target.
    Include findings when developing your test plan.
    Use get_result_page(pagination.next_page_token) for additional saved findings.
    A null next_page_token means there are no additional saved pages.
    """
    await log_tool_history(ctx, "query_findings", query=query, limit=limit)
    try:
        semantic_query, predicates = parse_finding_query(query)
    except ValueError as error:
        return QueryFindingsResult(
            instructions=f"Invalid finding query: {error}. Retry with site:example.com and optional search text.",
            query=query,
            limit=limit,
        )
    if semantic_query:
        if score_threshold is not None and (not math.isfinite(score_threshold) or not -1 <= score_threshold <= 1):
            raise ToolError("score_threshold must be finite and between -1 and 1 for semantic searches")

    server_ctx = await get_server_context()
    if semantic_query and server_ctx.low_power:
        return QueryFindingsResult(
            instructions=("Semantic finding search is unavailable in low-power mode. "
                          "Use predicates only for scoped retrieval."),
            query=query, limit=limit,
        )

    async def progress(message):
        try:
            await report_progress(ctx, message)
        except Exception:
            logger.debug("Finding progress notification unavailable", exc_info=True)

    await progress("Finding saved findings within scope")
    ids = await finding_ids(server_ctx.qdrant_client, predicates, FINDING_VERSION)
    await progress(f"Scope matched {len(ids)} findings")
    scores = {}
    truncated = False
    cap_reached = False
    if semantic_query and ids:
        await progress("Preparing semantic search")
        await server_ctx.finding_semantic_search.prepare()
        await progress("Embedding search query")
        embedding = await server_ctx.finding_semantic_search.embed(semantic_query)
        await progress("Ranking scoped findings")
        points, truncated = await rank_findings(
            server_ctx.qdrant_client, ids, embedding, score_threshold,
        )
        cap_reached = len(points) == FINDING_SEMANTIC_LIMIT
        ids = [point.id for point in points]
        scores = {str(point.id): point.score for point in points}
    await progress(f"Loading {len(ids)} matching findings")
    docs = await load_findings(server_ctx.qdrant_client, ids, scores)

    findings = []
    scope = next(p.value for p in predicates if p.operator == "site" and not p.exclude)
    for doc in docs:
        findings.append(Finding(
            finding_id=str(doc.id),
            metadata_revision=doc.meta.get("finding_metadata_revision", 1),
            metadata=doc.meta.get("finding_metadata", {}),
            metadata_conflicts=doc.meta.get("finding_metadata_conflicts", []),
            target=next((doc.meta[key] for key in ("url", "netloc", "host", "domain") if doc.meta.get(key)), scope),
            title=doc.meta.get("title", ""),
            markdown=doc.content,
            score=doc.score,
        ))

    logger.info(f"Found {len(findings)} findings")

    instructions = finding_instructions if findings else finding_not_found_instructions
    if semantic_query:
        instructions = (
            instructions if findings else
            "No saved findings met this semantic search within scope. Try different query terms or a lower "
            "score_threshold, or use predicates only for all scoped findings. Empty results do not establish security."
        )
        instructions += (
            " Results are ranked by similarity, not vulnerability confidence. "
            "This bounded snapshot is not an exhaustive review."
        )
    if cap_reached:
        instructions += (
            f" Search reached the {FINDING_SEMANTIC_LIMIT}-finding limit. "
            "Narrow the search with more specific terms or scope predicates."
        )
    return QueryFindingsResult(
        query=query,
        retrieval_truncated=truncated,
        instructions=instructions,
        limit=limit,
        findings=findings,
    )


class FindingInput(BaseModel):
    targets: List[str]
    title: str = ""
    markdown: str
    metadata: FindingMetadata | None = None


@mcp_instance.custom_route("/findings", methods=["POST"])
async def save_finding_api(request: Request) -> Response:
    """Validate all JSON/JSONL/form records before committing durable finding submissions."""
    content_type = request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    try:
        if content_type in {"application/json", "text/json"}:
            body = (await request.body()).decode("utf-8")
            try:
                records = [json.loads(body)]
            except json.JSONDecodeError:
                records = [json.loads(line) for line in body.splitlines() if line.strip()]
        elif content_type == "application/x-www-form-urlencoded":
            form = await request.form()
            records = [dict(form)]
            if "targets" in form:
                records[0]["targets"] = form.getlist("targets")
            if records[0].get("metadata"):
                records[0]["metadata"] = json.loads(records[0]["metadata"])
        else:
            return Response(status_code=400)
        if not records:
            raise ValueError("body: include at least one finding")
        findings = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(f"records.{index}: expected an object")
            if is_nuclei_finding(record):
                record = nuclei_finding_to_markdown(record)
            targets = record.get("targets", record.get("target", []))
            if isinstance(targets, str):
                targets = [targets]
            finding = FindingInput.model_validate({**record, "targets": targets})
            if not finding.targets or not finding.markdown.strip():
                raise ValueError(f"records.{index}: targets and markdown must not be empty")
            # Do not partially accept a multi-target record containing invalid targets.
            for target in finding.targets:
                parse_target_info(target)
            findings.append(finding)
    except (ValueError, TypeError, UnicodeError, ValidationError) as error:
        if isinstance(error, ValidationError):
            details = [{"field": ".".join(map(str, item["loc"])), "message": item["msg"]}
                       for item in error.errors()]
        else:
            details = [{"field": "body", "message": "Invalid finding body, targets, or metadata"}]
        return JSONResponse({"errors": details}, status_code=400)

    server_ctx = await get_server_context()
    for finding in findings:
        for target in finding.targets:
            await asyncio.to_thread(enqueue_finding, server_ctx.db, SaveFindingQueueItem(
                target=target, markdown=finding.markdown.strip(), title=finding.title.strip() or None,
                metadata=metadata_dict(finding.metadata),
            ))
    return Response(status_code=201)
