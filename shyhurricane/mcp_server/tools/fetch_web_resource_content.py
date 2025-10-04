import logging
from typing import Optional, Annotated

from haystack import Document
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, TextResourceContents
from pydantic import AnyUrl, Field

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server import get_server_context, mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import _run_unix_command
from shyhurricane.utils import HttpResource, TextResourcePartialContents, validate_container_file_path

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
        url: Annotated[str, Field(description="""The URL may be a http:// or https:// URL of a website that has been indexed, spidered or scanned.

    The URL may be a web://{doc_type}/{doc_id} URL supplied by the
    find_web_resources tool. The URL can be found in the resource_link JSON object.
""")],
        output_start_position: Annotated[
            int, Field(0, description="The character position in the resource to start output", ge=0)] = 0,
        output_length_limit: Annotated[
            int, Field(4096, description="Output length limit, truncates output if over this length.", ge=1,
                       le=4 * 1024 * 1024)] = 4096,
        save_path: Annotated[Optional[str], Field(
            description="Optional path for saving the content for further processing by the run_unix_command tool.")] = None,
) -> Optional[HttpResource]:
    """Fetch the content of a web resource that has already been indexed.

    Invoke this tool when:
     - the user requests analysis of resource content that has already been indexed, spidered or scanned
     - the user requests content with a URL that starts with "web://"

    If save_path is specified, the content will be available for further processing by the run_unix_command tool. After
    running this tool, use commands with run_unix_command to operate on the value of save_path.

    Javascript will have already been de-obfuscated when indexed.
    """
    await log_tool_history(ctx, "fetch_web_resource_content", url=url, save_path=save_path,
                           output_start_position=output_start_position, output_length_limit=output_length_limit)
    if save_path:
        validate_container_file_path(save_path, "save_path invalid")

    server_ctx = await get_server_context()
    doc_type: Optional[str] = None
    doc_id: Optional[str] = None
    doc: Optional[Document] = None
    logger.info("Fetching web resource %s", url)
    try_http_url = False
    if url.startswith("web://"):
        doc_type, doc_id = url.replace("web://", "").split("/", maxsplit=1)
        if "://" in doc_id:
            url = doc_id
            try_http_url = True
        else:
            doc = await _find_document_by_type_and_id(doc_type, doc_id)
    else:
        try_http_url = True

    if try_http_url:
        filters = {"operator": "AND",
                   "conditions": [
                       {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                       {"field": "meta.url", "operator": "==", "value": url},
                   ]}
        store = server_ctx.stores["content"]
        docs = store.filter_documents(filters=filters)
        if docs:
            logger.info("Found indexed web resource %s", url)
            doc = docs[0]
            doc_type = "content"
            doc_id = doc.id
    if not doc or not doc.content:
        return None

    if save_path:
        await _run_unix_command(ctx, f"cat > '{save_path}'", None, stdin=doc.content)

    if output_start_position >= len(doc.content):
        text = ""
    else:
        text = doc.content[output_start_position:output_start_position + output_length_limit]

    logger.info("Returning %d/%d @ %d bytes for %s/%s", output_length_limit, len(doc.content), output_start_position,
                doc_type, doc_id)

    contents = TextResourcePartialContents(
        uri=AnyUrl(url),
        mimeType=doc.meta.get('content_type', None),
        text=text,
        total_length=len(doc.content),
        offset=output_start_position,
        has_more=(output_start_position + output_length_limit < len(doc.content)),
    )
    return HttpResource.from_doc(doc, contents=contents)


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
