import logging
from typing import Optional, Annotated

from haystack import Document
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, TextResourceContents
from pydantic import AnyUrl, Field

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server import get_server_context, mcp_instance, log_tool_history

logger = logging.getLogger(__name__)


async def _find_document_by_type_and_id(doc_type: str, doc_id: str) -> Optional[Document]:
    server_ctx = await get_server_context()
    store = server_ctx.stores.get(doc_type, None)
    if not store:
        logger.info("Not Found document type %s", doc_type)
        return None
    filters = {"field": "id", "operator": "==", "value": doc_id}
    result = await store.filter_documents_async(filters=filters)
    if not result:
        logger.info("Not Found document %s/%s", doc_type, doc_id)
        return None
    doc: Document = result[0]
    logger.info("Found document %s", doc.id)
    return doc


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Fetch Web Resource Content",
        readOnlyHint=True,
        openWorldHint=False),
)
async def fetch_web_resource_content(
        ctx: Context,
        uri: Annotated[str, Field(description="""The URI may be a http:// or https:// URI of a website that has been indexed.

    The URI may be a web://{doc_type}/{doc_id} URI supplied by the
    find_web_resources tool. The URI can be found in the resource_link JSON object.
""")]
) -> Optional[TextResourceContents]:
    """Fetch the content of a web resource that has already been indexed.

    Invoke this tool when the user requests analysis of resource content that has already been indexed, spidered or scanned.
    """
    await log_tool_history(ctx, "fetch_web_resource_content", uri=uri)
    server_ctx = await get_server_context()
    doc_type: Optional[str] = None
    doc_id: Optional[str] = None
    doc: Optional[Document] = None
    logger.info("Fetching web resource %s", uri)
    try_http_url = False
    if uri.startswith("web://"):
        doc_type, doc_id = uri.replace("web://", "").split("/", maxsplit=1)
        if "://" in doc_id:
            uri = doc_id
            try_http_url = True
        else:
            doc = await _find_document_by_type_and_id(doc_type, doc_id)
    else:
        try_http_url = True

    if try_http_url:
        filters = {"operator": "AND",
                   "conditions": [
                       {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                       {"field": "meta.url", "operator": "==", "value": uri},
                   ]}
        store = server_ctx.stores["content"]
        docs = store.filter_documents(filters=filters)
        if docs:
            logger.info("Found indexed web resource %s", uri)
            doc = docs[0]
            doc_type = "content"
            doc_id = doc.id
    if not doc:
        return None
    logger.info("Returning %d bytes for %s/%s", len(doc.content), doc_type, doc_id)
    return TextResourceContents(
        uri=AnyUrl(uri),
        mimeType=doc.meta.get('content_type', None),
        text=doc.content,
    )


@mcp_instance.resource("web://{doc_type}/{doc_id}", title="Web Resource")
async def web_resource(doc_type: str, doc_id: str) -> Optional[TextResourceContents]:
    """
    Fetch a document using the type and document ID.
    """
    doc: Document = await _find_document_by_type_and_id(doc_type, doc_id)
    if doc is None:
        return None
    return TextResourceContents(
        uri=AnyUrl(f"web://{doc_type}/{doc_id}"),
        mimeType=doc.meta.get('content_type', None),
        text=doc.content,
    )
