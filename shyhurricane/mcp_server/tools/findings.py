import asyncio
import json
import logging
from typing import List, Optional

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from openai import BaseModel
from pydantic import Field
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context
from shyhurricane.target_info import parse_target_info, filter_targets_str
from shyhurricane.task_queue import SaveFindingQueueItem
from shyhurricane.task_queue.finding_worker import FINDING_VERSION
from shyhurricane.utils import munge_urls

logger = logging.getLogger(__name__)

finding_target_invalid_instructions = "Target must be a valid URL, host name, IP address, host:port or ip:port. Retry with a corrected target."
finding_not_found_instructions = "No findings found for the target. Expand the target or hack more!"
finding_instructions = "These findings were found for the target. They provide a good starting place to continue testing."


class SaveFindingResult(BaseModel):
    instructions: str = Field(description="Instructions for processing the result")
    target: str = Field(description="Target of the finding")
    title: Optional[str] = Field(description="Title of the finding")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Save Finding",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False),
)
async def save_finding(ctx: Context, target: str, markdown: str, title: Optional[str]) -> SaveFindingResult:
    """
    Use this tool to save **every finding** associated with the current target.
    A finding must be saved as soon as it is identified.

    #### Target:
    - Must be a URL, IP address, domain name, or hostname.
    - Port numbers may be included using a colon suffix (e.g. `target.local:8080`).

    #### Title:
    - A short, descriptive summary of the issue (one line max).

    #### Markdown:
    - The full body of the finding in **Markdown format**.
    - Each finding must include all the following sections:

      - **Title** – A concise, descriptive heading.
      - **Issue Summary** – What is wrong and why it is important.
      - **Discovery Method** – How the issue was found (tool or technique used).
      - **Reproduction Steps** – Step-by-step instructions to reproduce the issue.
      - **PoC** – Exploit code, request sample, or screenshot (if applicable).
      - **Fix** – Recommended remediation or mitigation.
      - **References** – Relevant CVEs, OWASP links, research articles, etc.

    Do not skip or omit this tool. **All findings must be saved.**
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
    await asyncio.to_thread(server_ctx.task_queue.put, SaveFindingQueueItem(
        target=target,
        markdown=markdown,
        title=title,
    ))

    return SaveFindingResult(
        instructions="Finding has been saved and can be retrieved later.",
        target=target,
        title=title,
    )


class Finding(BaseModel):
    target: str = Field(description="Target of the finding")
    title: str = Field(description="Title of the finding")
    markdown: str = Field(description="Markdown of the finding")


class QueryFindingsResult(BaseModel):
    instructions: str = Field(description="Instructions for processing the findings")
    target: str = Field(description="Target of the findings")
    limit: int = Field(description="Limit for the number of results")
    findings: List[Finding] = Field(default=[], description="Findings associated with the target")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Query for Findings",
        readOnlyHint=True,
        openWorldHint=False),
)
async def query_findings(ctx: Context, target: str, limit: int = 100) -> QueryFindingsResult:
    """
    Query for previous findings for the target. The findings provide a good starting place to continue testing.

    Invoke this tool when the user asks for existing vulnerabilities or is looking for a direction for testing a target.
    Include findings when developing your test plan.

    The target must be a URL, host name, IP address, or domain name.
    """
    await log_tool_history(ctx, "query_findings", target=target, limit=limit)
    server_ctx = await get_server_context()
    limit = min(1000, max(10, limit or 100))

    try:
        target_info = parse_target_info(target)
    except ValueError:
        return QueryFindingsResult(
            instructions=finding_target_invalid_instructions,
            target=target,
            limit=limit,
        )

    store = server_ctx.stores["finding"]
    docs = []

    if target_info.url:
        url_prefix, urls_munged = munge_urls(target_info.url)
        logger.info("Searching for findings for %s", urls_munged)
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": FINDING_VERSION},
                {"field": "meta.url", "operator": "in", "value": urls_munged}
            ]}
        logger.info("Query findings by url %s", filters)
        docs.extend(await store.filter_documents_async(filters=filters))
    elif target_info.netloc:
        logger.info("Searching for findings for %s", target_info.netloc)
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": FINDING_VERSION},
                {"field": "meta.netloc", "operator": "==", "value": target_info.netloc}
            ]}
        logger.info("Query findings by netloc %s", filters)
        docs.extend(await store.filter_documents_async(filters=filters))
    elif target_info.host:
        logger.info("Searching for findings for %s", target_info.host)
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": FINDING_VERSION},
                {"field": "meta.host", "operator": "==", "value": target_info.host}
            ]}
        logger.info("Query findings by host %s", filters)
        docs.extend(await store.filter_documents_async(filters=filters))
    elif target_info.domain:
        logger.info("Searching for findings for %s", target_info.domain)
        filters = {
            "operator": "AND",
            "conditions": [
                {"field": "meta.version", "operator": "==", "value": FINDING_VERSION},
                {"field": "meta.domain", "operator": "==", "value": target_info.domain}
            ]}
        logger.info("Query findings by domain %s", filters)
        docs.extend(await store.filter_documents_async(filters=filters))

    findings = []
    for doc in docs:
        findings.append(Finding(
            target=doc.meta.get("url", doc.meta.get("netloc", doc.meta.get("host", doc.meta.get("domain", target)))),
            title=doc.meta.get("title", ""),
            markdown=doc.content,
        ))
        if len(findings) >= limit:
            break

    return QueryFindingsResult(
        instructions=finding_instructions if len(findings) else finding_not_found_instructions,
        target=target,
        limit=limit,
        findings=findings,
    )


@mcp_instance.custom_route('/findings', methods=['POST'])
async def save_finding_api(request: Request) -> Response:
    if request.headers.get("Content-Type") in ["application/json", "text/json"]:
        try:
            parsed_json = await request.json()
            targets = parsed_json.get("targets", [parsed_json.get("target", "")])
            markdown = parsed_json.get("markdown", "").strip()
            title = parsed_json.get("title", "").strip()
        except json.decoder.JSONDecodeError:
            return Response(status_code=400)
    elif request.headers.get("Content-Type") == "application/x-www-form-urlencoded":
        try:
            form = await request.form()
            targets = form.get("targets", form.get("target", ""))
            markdown = form.get("markdown", "").strip()
            title = form.get("title", "").strip()
        except Exception:
            return Response(status_code=400)
    else:
        return Response(status_code=400)

    if isinstance(targets, str):
        targets = [targets]

    targets = filter_targets_str(targets)
    if not targets or not markdown:
        return Response(status_code=400)

    server_ctx = await get_server_context()
    for target in targets:
        await asyncio.to_thread(server_ctx.task_queue.put, SaveFindingQueueItem(
            target=target,
            markdown=markdown,
            title=title or None,
        ))

    return Response(status_code=201)
