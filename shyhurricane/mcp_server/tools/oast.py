import asyncio
import time
from typing import Annotated

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.oast import Endpoints, PollOutput, HealthOutput


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="OAST Health Check",
        readOnlyHint=True,
        openWorldHint=True,
    )
)
async def oast_health(ctx: Context) -> HealthOutput:
    """
    Check the health/reachability of the currently configured OAST provider.
    """
    await log_tool_history(ctx, "oast.health")
    try:
        return await ctx.request_context.lifespan_context.oast_provider.health()
    except Exception as e:
        return HealthOutput(status="error", detail=str(e))


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="OAST Endpoints",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True
    )
)
async def oast_endpoints(ctx: Context) -> Endpoints:
    """
    Get the endpoints that can be used to test out-of-band interactions from the target (always known as OAST).
    The result is a map of supported service types to endpoint. Service types include http, https, dns, email, etc.

    Invoke this tool when the user wants to use out-of-band services to verify vulnerabilities or run exploits such as
    XSS, blind command injection, etc.

    After using one of the endpoints in the target, the oast.poll tool is used to poll for interactions with the endpoints.
    Payloads in the query string or POST data will be available from the oast.poll tool call. If the email service is
    supported, any emails send to the email address will be available in the oast.poll tool.

    For XSS testing, the payload can be used to exfiltrate sensitive information such as cookies and localStorage by
    passing the values in a query string or POST data.
    """
    await log_tool_history(ctx, "oast.endpoints")
    return await ctx.request_context.lifespan_context.oast_provider.init()


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="OAST Poll Interactions",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True
    )
)
async def oast_poll(
        ctx: Context,
        timeout: Annotated[float, Field(
            30.0,
            description=(
                    "The number of seconds to wait for interactions. A value of 0 returns immediately with any pending "
                    "interactions."
            ),
            ge=0.0, le=600.0
        )] = 30.0,
) -> PollOutput:
    """
    Retrieve new interactions with the OAST service since the last poll.

    Invoke this tool when the user wants to check for interactions from the target to the OAST service.
    """
    await log_tool_history(ctx, "oast_poll", timeout=timeout)
    time_end = time.time() + timeout
    time_step = 3.0
    while time.time() < time_end:
        result = await ctx.request_context.lifespan_context.oast_provider.poll_new()
        if len(result.interactions) > 0:
            await log_tool_history(ctx, f"oast_poll returned {len(result.interactions)} interactions", timeout=timeout)
            return result
        await asyncio.sleep(min(time_step, time_end - time.time()))
    await log_tool_history(ctx, "oast_poll returned 0 interactions", timeout=timeout)
    return PollOutput()
