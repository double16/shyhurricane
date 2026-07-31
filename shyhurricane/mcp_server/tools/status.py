import json
import os

from qdrant_client import AsyncQdrantClient
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.persistent_queue import active_queue_size, get_doc_type_queue
from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.db import get_domain_and_host_counts


@mcp_instance.custom_route('/status', methods=['POST'])
async def status(request: Request) -> Response:
    """
    Returns various statistics and runtime status for the MCP server.
    """
    server_ctx = await get_server_context()
    doc_type_queue = get_doc_type_queue(server_ctx.db)
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client

    document_counts = {}
    for collection_name, store in server_ctx.stores.items():
        document_counts[collection_name] = await store.count_documents_async()

    domain_counts, host_counts = await get_domain_and_host_counts(qdrant_client, WEB_RESOURCE_VERSION)

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
            "index_active": active_queue_size(server_ctx.ingest_queue),
            "type_specific_index_active": active_queue_size(doc_type_queue),
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
