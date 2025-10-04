import logging
from typing import Annotated

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import _run_unix_command, RunUnixCommand
from shyhurricane.utils import validate_container_file_path

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
    Deobfuscate JavaScript to resemble the original source.

    Invoke this tool when the user needs to deobfuscate, unpack and/or un-minify JavaScript to aid in understanding.
    """
    await log_tool_history(ctx, "deobfuscate_javascript_content", content=content[0:128])
    if content is None or not content.strip():
        return ""
    result = await _run_unix_command(ctx, "timeout --preserve-status --kill-after=1m 10m /usr/local/bin/jsdeobf.sh",
                                     None, content)
    if result is None or result.return_code != 0:
        return content
    return result.output


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="De-obfuscate Javascript files",
        readOnlyHint=True,
        openWorldHint=False),
)
async def deobfuscate_javascript_file(
        ctx: Context,
        input_path: Annotated[str, Field(description="Path to Javascript file to deobfuscate, in the run_unix_command container")],
        output_path: Annotated[str, Field(description="Output path for deobfuscated Javascript, in the run_unix_command container")],
) -> RunUnixCommand:
    """
    Deobfuscate a JavaScript file to resemble the original source. The input_path and output_path are available in the
    `run_unix_command` tool for further processing.

    Invoke this tool when the user needs to deobfuscate, unpack and/or un-minify JavaScript to aid in understanding.
    """
    await log_tool_history(ctx, "deobfuscate_javascript_file", input_path=input_path, output_path=output_path)
    validate_container_file_path(input_path, "input_path invalid")
    validate_container_file_path(output_path, "output_path invalid")
    result = await _run_unix_command(ctx, f"timeout --preserve-status --kill-after=1m 10m /usr/local/bin/jsdeobf.sh '{input_path}' '{output_path}'",
                                     None)
    return result
