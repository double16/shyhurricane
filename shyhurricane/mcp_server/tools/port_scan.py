import asyncio
import logging
import queue
import time
from multiprocessing import Queue
from typing import Optional, List, Dict

from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context, get_additional_hosts
from shyhurricane.task_queue import PortScanQueueItem
from shyhurricane.task_queue.port_scan_worker import get_stored_port_scan_results
from shyhurricane.utils import filter_hosts_and_addresses, filter_ip_networks, PortScanResults

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
        hostnames: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        ip_subnets: Optional[str] = None,
        ports: Optional[List[int]] = None,
        port_range_low: Optional[int] = None,
        port_range_high: Optional[int] = None,
        additional_hosts: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
        retry: bool = False,
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

    The ports parameter is a list of individual ports to scan.
    The port_range_low and port_range_high allow specifying a range of ports to scan.
    By not specifying ports, port_range_low and port_range_high, all ports will be scanned.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    If the port scan reveals additional host names, use the `register_hostname_address` tool to register them.

    The timeout_seconds parameter specifies how long to wait for responses before returning. Port scanning will
    continue after returning.

    The port scan may take a long time, and this tool may return before the scan is finished.
    If a timeout occurs, call this tool again with the same parameters, and it will return indexed results.
    """
    await log_tool_history(ctx, "port_scan", hostnames=hostnames, ip_addresses=ip_addresses, ip_subnets=ip_subnets,
                           ports=ports, port_range_low=port_range_low, port_range_high=port_range_high,
                           additional_hosts=additional_hosts, timeout_seconds=timeout_seconds)

    server_ctx = await get_server_context()
    assert server_ctx.open_world

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
        except (queue.Empty, TimeoutError):
            break
        if results_from_queue is None:
            continue
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
