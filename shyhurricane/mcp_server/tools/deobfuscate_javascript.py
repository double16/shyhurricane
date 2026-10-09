import logging
from typing import Annotated

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import log_tool_history, mcp_instance
from shyhurricane.result_pages import SavedTextResult, paged_content

from ..run_unix_command import _run_unix_command

logger = logging.getLogger(__name__)


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
) -> SavedTextResult:
    """Deobfuscate JavaScript to resemble the original source.

    Invoke this tool when the user needs to deobfuscate, unpack and/or un-minify JavaScript to aid in understanding.
    """
    await log_tool_history(ctx, "deobfuscate_javascript_content", content=(content or "")[0:128])
    text = await deobfuscate_javascript_full(ctx, content)
    return SavedTextResult(text=text, mime_type="application/javascript", total_length=len(text))


async def deobfuscate_javascript_full(ctx: Context, content: str) -> str:
    """Transform complete content for indexing and public preview construction."""
    if content is None or not content.strip():
        return ""
    result = await _run_unix_command(ctx, "timeout --preserve-status --kill-after=1m 10m /usr/local/bin/jsdeobf.sh",
                                     None, content)
    if result is None or result.return_code != 0:
        return content
    return result.output
