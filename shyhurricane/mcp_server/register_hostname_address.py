from typing import Dict

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_additional_hosts

register_hostname_address_lifetime_instructions = "All of the host names included here will be mapped to their corresponding IP addresses without the need for DNS for the lifetime of the conversation."

register_hostname_address_instructions = "The host name {0} has been successfully mapped to the IP address {1}. " + register_hostname_address_lifetime_instructions

register_hostname_address_instructions_already_mapped = "The host name {0} is already mapped to the IP address {1}, there is no need to register it again. " + register_hostname_address_lifetime_instructions

register_hostname_address_instructions_error = "The host name or IP address was malformed and not registered."


class RegisterHostnameAddressResult(BaseModel):
    instructions: str = Field(description="The instructions string for interpreting the results")
    host_to_address: Dict[str, str] = Field(description="The host to address mapping")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Register Hostname Address",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False),
)
async def register_hostname_address(ctx: Context, host: str, address: str) -> RegisterHostnameAddressResult:
    """
    Registers a hostname with an IP address. This is useful when a hostname has no DNS entry
    and we know the IP address by other means. Especially useful in CTF or private networks.

    Invoke this tool when another tool has found an additional host name for a target in-scope.

    Invoke this tool when the user asks to register a hostname with an IP address.
    """
    await log_tool_history(ctx, "register_hostname_address", host=host, address=address)

    existing = get_additional_hosts(ctx)
    if existing.get(host, "") == address:
        return RegisterHostnameAddressResult(
            instructions=register_hostname_address_instructions_already_mapped.format(host, address),
            host_to_address=existing,
        )

    results = get_additional_hosts(ctx, {host: address})
    if results.get(host, "") == address:
        return RegisterHostnameAddressResult(
            instructions=register_hostname_address_instructions.format(host, address),
            host_to_address=results,
        )
    else:
        return RegisterHostnameAddressResult(
            instructions=register_hostname_address_instructions_error.format(host, address),
            host_to_address={},
        )
