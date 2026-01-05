import json
import os
from typing import Dict

from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.persistent_queue import get_doc_type_queue
from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.db import scroll_qdrant_collection


@mcp_instance.custom_route('/status', methods=['POST'])
async def status(request: Request) -> Response:
    """
    Returns various statistics and runtime status for the MCP server.
    """
    server_ctx = await get_server_context()
    doc_type_queue = get_doc_type_queue(server_ctx.db)
    qdrant_client: AsyncQdrantClient = server_ctx.qdrant_client

    document_counts = {}
    domain_counts: Dict[str, int] = {}
    host_counts: Dict[str, int] = {}
    for collection_name, store in server_ctx.stores.items():
        document_counts[collection_name] = await store.count_documents_async()

    filters = qm.Filter(
        must=[
            qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
        ]
    )
    async for record in scroll_qdrant_collection(qdrant_client=qdrant_client, index="network", fields=["meta"],
                                                 scroll_filter=filters):
        metadata = record.payload["meta"]
        if "domain" in metadata:
            domain = metadata['domain'].lower()
            if domain in domain_counts:
                domain_counts[domain] += 1
            else:
                domain_counts[domain] = 1
        if "host" in metadata:
            host = metadata['host'].lower()
            if host in host_counts:
                host_counts[host] += 1
            else:
                host_counts[host] = 1

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
            "index_active": server_ctx.ingest_queue.active_size(),
            "type_specific_index_active": doc_type_queue.active_size(),
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
