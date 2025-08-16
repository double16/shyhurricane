import logging
from typing import Annotated

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import _run_unix_command

logger = logging.getLogger(__name__)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="De-obfuscate Javascript",
        readOnlyHint=True,
        openWorldHint=False),
)
async def deobfuscate_javascript(
        ctx: Context,
        content: Annotated[str, Field(description="Javascript content to deobfuscate")]
) -> str:
    """
    Deobfuscate a JavaScript file to be closer to the original source.

    Invoke this tool when the user needs to deobfuscate, unpack and/or un-minify JavaScript to aid in understanding.
    """
    await log_tool_history(ctx, "deobfuscate_javascript", content=content[0:128])
    if content is None or not content.strip():
        return ""
    result = await _run_unix_command(ctx, "timeout --preserve-status --kill-after=1m 90s /usr/share/wakaru/wakaru.cjs",
                                     None, content)
    if result is None or result.return_code != 0:
        return content
    return result.output
