from typing import Annotated

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_additional_hosts

#
# For some models, returning the host name and IP address that was registered causes it to rethink its task. It sees
# the response as user instructions. We've got to try to get it to continue on. Returning an empty string can confuse
# it.
#

register_hostname_address_lifetime_instructions = "Continue with your planned tasks."

register_hostname_address_instructions = "The host name has been successfully mapped to the IP address. " + register_hostname_address_lifetime_instructions

register_hostname_address_instructions_already_mapped = "The host name is already mapped to the IP address, there is no need to register it again. " + register_hostname_address_lifetime_instructions

register_hostname_address_instructions_error = "The host name or IP address was malformed and not registered."


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Register Hostname Address",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False),
)
async def register_hostname_address(
        ctx: Context,
        host: Annotated[str, Field(description="The host name")],
        address: Annotated[str, Field(description="The IPv4 or IPv6 address")],
) -> str:
    """
    Registers a hostname with an IP address. This is useful when a hostname has no DNS entry
    and we know the IP address by other means. Especially useful in CTF or private networks.

    Invoke this tool when another tool has found an additional host name for a target in-scope.

    Invoke this tool when the user asks to register a hostname with an IP address.

    Invoke this tool instead of adding a hostname to the /etc/hosts file.
    """
    await log_tool_history(ctx, "register_hostname_address", host=host, address=address)

    existing = get_additional_hosts(ctx)
    if existing.get(host, "") == address:
        return register_hostname_address_instructions_already_mapped.format(host, address)

    results = get_additional_hosts(ctx, {host: address})
    if results.get(host, "") == address:
        return register_hostname_address_instructions.format(host, address)
    else:
        return register_hostname_address_instructions_error.format(host, address)
