import asyncio
import json
import os

from qdrant_client import AsyncQdrantClient
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.db import get_domain_and_host_counts
from shyhurricane.disk_space import disk_status
from shyhurricane.graph.status import graph_status
from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server import get_server_context, mcp_instance
from shyhurricane.monitoring_qdrant import bounded_count
from shyhurricane.persistent_queue import persistent_queue_counts


@mcp_instance.custom_route('/status', methods=['POST'])
async def status(request: Request) -> Response:
    """
    Returns various statistics and runtime status for the MCP server.
    """
    server_ctx = await get_server_context()
    queues = await persistent_queue_counts(server_ctx.db)
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client

    # Fresh, exact data; errors propagate instead of publishing partial or cached counts.
    names = list(server_ctx.stores)
    tasks = [asyncio.create_task(bounded_count(server_ctx.stores[name])) for name in names]
    tasks.append(asyncio.create_task(get_domain_and_host_counts(qdrant_client, WEB_RESOURCE_VERSION)))
    try:
        async with asyncio.timeout(10):
            *results, (domain_counts, host_counts) = await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    document_counts = dict(zip(names, results, strict=True))

    if server_ctx.proxy_ca_cert_path:
        with open(server_ctx.proxy_ca_cert_path) as f:
            ca_cert_str = f.read()
    else:
        ca_cert_str = None
    return Response(
        status_code=200,
        media_type="application/json",
        content=json.dumps({
            "document_counts": document_counts,
            "domain_counts": domain_counts,
            "host_counts": host_counts,
            "queues": queues,
            "disk": disk_status(server_ctx),
            "graph": await graph_status(server_ctx),
            "proxy_host": server_ctx.proxy_host,
            "proxy_port": server_ctx.proxy_port,
            "proxy_ca_cert": ca_cert_str,
        })
    )


@mcp_instance.custom_route('/favicon.ico', methods=['GET'])
async def favicon(request: Request) -> Response:
    with open(os.path.join(os.path.dirname(__file__), "../../assets/favicon.ico"), "rb") as f:
        return Response(
            status_code=200,
            media_type="image/x-icon",
            content=f.read(),
        )
