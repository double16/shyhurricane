from typing import Dict

import chromadb
from chromadb.api.models import AsyncCollection
from mcp.types import ToolAnnotations
from pydantic import Field, BaseModel

from shyhurricane.index.web_resources import get_doc_type_queue
from shyhurricane.mcp_server import mcp_instance, get_server_context


class StatusResult(BaseModel):
    document_counts: Dict[str, int] = Field("The count of documents in  each document collection")
    domain_counts: Dict[str, int] = Field("The count of documents for each domain")
    host_counts: Dict[str, int] = Field("The count of documents for each host")
    index_active: int = Field("The number of active requests to index (light-weight)")
    type_specific_index_active: int = Field(
        "The number of active requests to index type-specific information (heavy-weight)")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Status Report",
        readOnlyHint=True,
        openWorldHint=False),
)
async def status() -> StatusResult:
    """
    Returns various statistics and runtime status for the MCP server.
    """
    server_ctx = await get_server_context()
    doc_type_queue = get_doc_type_queue(server_ctx.db)
    chroma_client: chromadb.AsyncClientAPI = server_ctx.chroma_client
    collection: AsyncCollection = await chroma_client.get_collection("network")

    document_counts = {}
    domain_counts: Dict[str, int] = {}
    host_counts: Dict[str, int] = {}
    for collection_name, store in server_ctx.stores.items():
        document_counts[collection_name] = await store.count_documents_async()

        count = await collection.count()
        limit = 1000
        offset = 0
        while offset < count:
            get_result = await collection.get(
                include=["metadatas"],
                limit=limit,
                offset=offset,
            )
            offset += limit
            metadatas = get_result.get("metadatas", [])
            for metadata in metadatas:
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

    return StatusResult(
        document_counts=document_counts,
        domain_counts=domain_counts,
        host_counts=host_counts,
        index_active=server_ctx.ingest_queue.active_size(),
        type_specific_index_active=doc_type_queue.active_size(),
    )
