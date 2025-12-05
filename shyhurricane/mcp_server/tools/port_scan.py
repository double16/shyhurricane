import asyncio
import logging
import queue
import time
from multiprocessing import Queue
from typing import Optional, List, Annotated, Union

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context, get_additional_hosts, \
    AdditionalHostsField
from shyhurricane.task_queue import PortScanQueueItem
from shyhurricane.task_queue.port_scan_worker import get_stored_port_scan_results
from shyhurricane.utils import filter_hosts_and_addresses, filter_ip_networks, PortScanResults, coerce_to_list, \
    coerce_to_dict

logger = logging.getLogger(__name__)

port_scan_instructions = "These are the port scan results formatted as nmap XML."
port_scan_instructions_pending = "These are partial results from the port scan, formatted as nmap XML. The scan is still running. Running the port scan again with the same parameters will return indexed results."
port_scan_instructions_no_results = "No port scan results are available at this time. The scan is still running. Running the port scan again with the same parameters will return indexed results."


class PortScanToolResult(BaseModel):
    instructions: str = Field(description="The instructions for interpreting the results")
    hostnames: Optional[List[str]] = Field(description="The hostnames that were scanned")
    ip_addresses: Optional[List[str]] = Field(description="The IP addresses that were scanned")
    ip_subnets: Optional[List[str]] = Field(description="The IP subnets that were scanned")
    ports: List[str] = Field(description="The ports that were scanned")
    nmap_xml: Optional[str] = Field(description="The port scan results formatted as nmap XML")
    has_more: bool = Field(
        description="Whether the port scan has more results available that can be retrieved by calling port_scan with the same parameters again")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Perform port scanning and service identification on target(s)",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def port_scan(
        ctx: Context,
        hostnames: Optional[Union[List[str], str]] = None,
        ip_addresses: Optional[Union[List[str], str]] = None,
        ip_subnets: Optional[Union[List[str], str]] = None,
        ports: Annotated[
            Optional[Union[List[int], str]],
            Field(None, description="List of individual ports to scan, leave empty for all ports")
        ] = None,
        port_range_low: Annotated[
            Optional[int],
            Field(None, description="The low end of the optional port range", ge=1, le=65535)
        ] = None,
        port_range_high: Annotated[
            Optional[int],
            Field(None, description="The high end of the optional port range", ge=1, le=65535)
        ] = None,
        additional_hosts: AdditionalHostsField = None,
        timeout_seconds: Annotated[
            Optional[int],
            Field(120,
                  description="How long to wait, in seconds, for responses before returning. The port scan will continue after returning.",
                  ge=30, le=600,
                  )
        ] = None,
        retry: Annotated[
            bool,
            Field(False,
                  description="Set to true to force retrying the port scan. Only use true if the results are suspected to be invalid, such as a temporary network failure."
                  )
        ] = False,
) -> PortScanToolResult:
    """
    Performs a port scan and service identification on the target(s), similar to the functions of nmap.
    The results are indexed to allow later retrieval. The output format is that of nmap.

    Invoke this tool when the user needs to identify which services are running on the targets in-scope.
    Use this tool instead of nmap or rustscan unless the user wants to run specific nmap NSE scripts, then
    use the run_unix_command tool.

    One of hostnames, ip_addresses, or ip_subnets must be specified. The hostnames parameter is a list of hostnames and
    may require entries in additional_hosts if the IP address is known for a hostname. The ip_addresses parameters is
    a list of IPv4 or IPv6 addresses. The ip_subnets parameter is a list of IPv4 or IPv6 subnets in CIDR notation, such
    as "192.168.1.0/24".

    If the port scan reveals additional hostnames, virtual hosts or redirects, use the `register_hostname_address` tool to register them.

    The port scan may take a long time, and this tool may return before the scan is finished.
    If a timeout occurs, call this tool again with the same parameters, and it will return indexed results.
    """

    # Coerce types
    hostnames = coerce_to_list(hostnames)
    ip_addresses = coerce_to_list(ip_addresses)
    ip_subnets = coerce_to_list(ip_subnets)
    ports = coerce_to_list(ports, int)
    additional_hosts = coerce_to_dict(additional_hosts)

    await log_tool_history(ctx, "port_scan", hostnames=hostnames, ip_addresses=ip_addresses, ip_subnets=ip_subnets,
                           ports=ports, port_range_low=port_range_low, port_range_high=port_range_high,
                           additional_hosts=additional_hosts, timeout_seconds=timeout_seconds)

    server_ctx = await get_server_context()
    assert server_ctx.open_world
    context_id = ctx.request_context.lifespan_context.app_context_id

    port_scan_queue: Queue = server_ctx.task_queue
    port_scan_result_queue: Queue = server_ctx.port_scan_result_queue

    hostnames = filter_hosts_and_addresses(hostnames)
    ip_addresses = filter_hosts_and_addresses(ip_addresses)
    ip_subnets = filter_ip_networks(ip_subnets)

    ports_list = list(map(str, ports or []))
    if port_range_low or port_range_high:
        low_port = max(1, min(port_range_low or 1, port_range_high or 65535))
        high_port = min(65535, max(port_range_low or 1, port_range_high or 65535))
        ports_list.append(f"{low_port}-{high_port}")
    port_scan_queue_item = PortScanQueueItem(
        context_id=context_id,
        targets=(hostnames or []) + (ip_addresses or []) + (ip_subnets or []),
        ports=ports_list,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
        retry=retry,
    )

    if not port_scan_queue_item.targets:
        return PortScanToolResult(
            instructions="No targets were specified. Specify a target in hostnames, ip_addresses, or ip_subnets.",
            hostnames=hostnames,
            ip_addresses=ip_addresses,
            ip_subnets=ip_subnets,
            ports=ports_list,
            nmap_xml=None,
            has_more=False,
        )

    if not retry:
        if stored_results := get_stored_port_scan_results(
                port_scan_queue_item,
                server_ctx.stores["nmap"],
                server_ctx.stores["portscan"],
        ):
            logger.info("Returning stored port scan results for %s", port_scan_queue_item.targets)
            return PortScanToolResult(
                instructions=port_scan_instructions,
                hostnames=hostnames,
                ip_addresses=ip_addresses,
                ip_subnets=ip_subnets,
                ports=ports_list,
                nmap_xml=stored_results.nmap_xml,
                has_more=False,
            )

    await asyncio.to_thread(port_scan_queue.put, port_scan_queue_item)
    results: Optional[PortScanResults] = None
    time_limit = time.time() + min(600, max(30, timeout_seconds or 120))
    while time.time() < time_limit:
        try:
            results_from_queue: PortScanResults = await asyncio.to_thread(
                port_scan_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
            if results_from_queue.context_id != context_id:
                if not results_from_queue.is_expired():
                    port_scan_result_queue.put(results_from_queue, block=False)
                    # wait so we don't get into a fast loop of putting back an item not for us
                    await asyncio.sleep(0.5)
                continue
        except (queue.Empty, TimeoutError):
            break
        logger.info(f"{results_from_queue.targets}, {results_from_queue.ports} has been retrieved")
        if results_from_queue.targets == port_scan_queue_item.targets:
            results = results_from_queue
            if not results.has_more:
                break

    if results:
        if results.has_more:
            instructions = port_scan_instructions_pending
        else:
            instructions = port_scan_instructions
    else:
        instructions = port_scan_instructions_no_results

    pending_results = PortScanToolResult(
        instructions=instructions,
        hostnames=hostnames,
        ip_addresses=ip_addresses,
        ip_subnets=ip_subnets,
        ports=ports_list,
        nmap_xml=results.nmap_xml if results else None,
        has_more=results.has_more if results else True,
    )
    logger.info("%s for %s", pending_results.instructions, port_scan_queue_item.targets)
    return pending_results
