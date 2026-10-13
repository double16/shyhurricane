import logging
from typing import Annotated, Literal

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import log_tool_history, mcp_instance
from shyhurricane.result_pages import SavedTextResult, paged_content

from ..run_unix_command import _run_unix_command

logger = logging.getLogger(__name__)


class DeobfuscationResult(SavedTextResult):
    transformation_status: Literal["empty", "succeeded", "failed", "unknown"] = Field(
        default="unknown",
        description="Command outcome; failed returns original input. Unknown marks older saved results.",
    )


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="De-obfuscate Javascript",
        read_only_hint=True,
        open_world_hint=False),
)
@paged_content("output_length_limit", "text")
async def deobfuscate_javascript(
        ctx: Context,
        content: Annotated[str, Field(description="Javascript content to deobfuscate")],
        output_length_limit: Annotated[int, Field(8192, ge=1, le=4 * 1024 * 1024,
                                                description="Characters per page")] = 8192,
) -> DeobfuscationResult:
    """Deobfuscate JavaScript to resemble the original source.

    Use this tool to deobfuscate, unpack or un-minify externally supplied JavaScript.
    Indexed JavaScript has already undergone automatic transformation; avoid repeating it without
    a reason. transformation_status reports empty input, command success or failure. Success does
    not guarantee complete recovery. Failure returns original input.
    Use get_result_page(pagination.next_page_token) for additional saved text.
    A null next_page_token means there are no additional saved pages.
    """
    await log_tool_history(ctx, "deobfuscate_javascript_content", content=(content or "")[0:128])
    text, status = await _transform_javascript(ctx, content)
    return DeobfuscationResult(
        text=text, mime_type="application/javascript", total_length=len(text), transformation_status=status
    )


async def deobfuscate_javascript_full(ctx: Context, content: str) -> str:
    """Transform complete content for indexing and public preview construction."""
    text, _ = await _transform_javascript(ctx, content)
    return text


async def _transform_javascript(
    ctx: Context, content: str
) -> tuple[str, Literal["empty", "succeeded", "failed"]]:
    """Return text and command outcome without assuming complete source recovery."""
    if content is None or not content.strip():
        return "", "empty"
    result = await _run_unix_command(ctx, "timeout --preserve-status --kill-after=1m 10m /usr/local/bin/jsdeobf.sh",
                                     None, content)
    if result is None or result.return_code != 0:
        return content, "failed"
    return result.output, "succeeded"
