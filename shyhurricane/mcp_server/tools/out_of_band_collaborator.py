from __future__ import annotations

import random
import httpx

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.server_config import get_server_config
from shyhurricane.outofband import Endpoints, PollOutput, OOBProvider, HealthOutput
from shyhurricane.outofband.burpcollab import BurpCollaboratorProvider
from shyhurricane.outofband.interactsh import InteractProvider, PUBLIC_SERVERS
from shyhurricane.outofband.webhook_site import WebhookSiteProvider

"""
# Pick one provider at startup via env vars
# 1) interact.sh
OOB_PROVIDER=interactsh \
INTERACT_SERVER=oast.pro \        # optional
INTERACT_TOKEN= \                 # optional (Bearer ...)
python oob_mcp_tool.py

# 2) webhook.site (unauth)
OOB_PROVIDER=webhook_site \
python oob_mcp_tool.py

# 2b) webhook.site (with API key)
OOB_PROVIDER=webhook_site \
WEBHOOK_API_KEY=xxxxxxxx-xxxx-... \
python oob_mcp_tool.py

# 3) Burp Collaborator (requires a local HTTP bridge to Burp)
OOB_PROVIDER=burp_collaborator \
export BURP_COLLAB_BRIDGE_URL=http://127.0.0.1:8009 \
export BURP_COLLAB_BRIDGE_SECRET=change-me \
python oob_mcp_tool.py
"""


def _provider() -> OOBProvider:
    server_config = get_server_config()
    if server_config.out_of_band.provider == "interactsh":
        return InteractProvider()
    if server_config.out_of_band.provider == "webhook_site":
        return WebhookSiteProvider()
    if server_config.out_of_band.provider == "burp_collaborator":
        return BurpCollaboratorProvider()
    raise RuntimeError(f"Unknown provider: {server_config.out_of_band}")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Out Of Band Health Check",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def out_of_band_health(ctx: Context) -> HealthOutput:
    """
    Check the health/reachability of the currently configured OAST provider.
    """
    await log_tool_history(ctx, "out_of_band_health")
    try:
        return await _provider().health(ctx.session)
    except Exception as e:
        return HealthOutput(status="error", detail=str(e))


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Out Of Band Collab Endpoints",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def out_of_band_endpoints(ctx: Context) -> Endpoints:
    """
    Return a map of service type to endpoint for the current session (fields are optional per provider).
    """
    await log_tool_history(ctx, "out_of_band_endpoints")
    return await _provider().init(ctx.session)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Out Of Band Collab Poll Interactions",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def out_of_band_poll(ctx: Context) -> PollOutput:
    """
    Retrieve new interactions since the last poll.
    """
    await log_tool_history(ctx, "out_of_band_poll")
    return await _provider().poll_new(ctx.session)
