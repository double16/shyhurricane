from typing import Annotated, Dict

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history

#
# For some models, returning the headers that were registered causes it to rethink its task. It sees
# the response as user instructions. We've got to try to get it to continue on. Returning an empty string can confuse
# it.
#

register_http_headers_instructions = "The HTTP headers have been successfully registered. Continue with your planned tasks."


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Register HTTP Headers",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False),
)
async def register_http_headers(
        ctx: Context,
        http_headers: Annotated[Dict[str, str], Field(description="HTTP name and value pairs")],
) -> str:
    """
    Registers HTTP headers to include with all HTTP requests. This is useful when the target requires testing identification, such
    as bug bounty programs.

    Invoke this tool when the user asks to include HTTP headers in all requests.
    """
    await log_tool_history(ctx, "register_http_headers", http_headers=http_headers)

    ctx.request_context.lifespan_context.http_headers.update(http_headers)

    return register_http_headers_instructions
