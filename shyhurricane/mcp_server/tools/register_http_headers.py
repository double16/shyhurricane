from typing import Annotated, Dict

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import log_tool_history, mcp_instance

#
# For some models, returning the headers that were registered causes it to rethink its task. It sees
# the response as user instructions. We've got to try to get it to continue on. Returning an empty string can confuse
# it.
#

register_http_headers_instructions = (
    "The HTTP headers are registered for this legacy session. Continue with your planned tasks."
)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Register HTTP Headers",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False),
)
async def register_http_headers(
        ctx: Context,
        http_headers: Annotated[Dict[str, str], Field(description="HTTP name and value pairs")],
) -> str:
    """Register HTTP headers to include with subsequent requests.

    Registers headers for subsequent HTTP tool requests in the current legacy session only.
    Per-call request_headers override registered values with the same key.
    Unavailable to modern clients; supply request_headers on every call that needs them.
    Use for testing identification or required authentication.

    Invoke this tool when the user asks to include HTTP headers in all requests.
    """
    await log_tool_history(ctx, "register_http_headers", http_headers=http_headers)

    ctx.request_context.lifespan_context.http_headers.update(http_headers)

    return register_http_headers_instructions
