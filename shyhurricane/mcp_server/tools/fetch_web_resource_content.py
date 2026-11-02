import logging
from typing import Annotated, Optional

from haystack import Document
from mcp.server.mcpserver import Context
from mcp.types import TextResourceContents, ToolAnnotations
from pydantic import Field
from qdrant_client.http import models as qm

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.indexing_wait import (
    IndexingOnlyResult,
    IndexingStatus,
    indexing_scope,
    url_matcher,
    wait_for_indexing,
)
from shyhurricane.mcp_server import get_server_context, log_tool_history, mcp_instance
from shyhurricane.qdrant_reads import read_documents, retrieve_records, to_document
from shyhurricane.utils import HttpResourceOffset, TextResourcePartialContents

logger = logging.getLogger(__name__)


class IndexedResourceContent(HttpResourceOffset):
    indexing: IndexingStatus | None = None


async def _find_document_by_type_and_id(doc_type: str, doc_id: str, *, metadata_only=False) -> Optional[Document]:
    server_ctx = await get_server_context()
    if doc_type not in server_ctx.stores:
        return None
    points = await retrieve_records(
        server_ctx.qdrant_client, doc_type, [doc_id], opaque_ids=True,
        fields=["id", "meta.url"] if metadata_only else True,
    )
    return to_document(points[0]) if points else None


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Fetch Web Resource Content",
        read_only_hint=True,
        open_world_hint=False),
)
@indexing_scope()
async def fetch_web_resource_content(
        ctx: Context,
        url: Annotated[str, Field(description="""The URL may be a http:// or https:// URL of a website that has been indexed, spidered or scanned.

    The URL may be a web://{doc_type}/{doc_id} URL supplied by the
    find_web_resources tool. Pass resource.uri from the structured record, or the URI
    from an MCP resource-link content block.
""")],
        output_start_position: Annotated[
            int, Field(0, description="The character position in the resource to start output", ge=0)] = 0,
        output_length_limit: Annotated[
            int, Field(4096, description="Output length limit, truncates output if over this length.", ge=1,
                       le=4 * 1024 * 1024)] = 4096,
) -> IndexedResourceContent | IndexingOnlyResult | None:
    """Fetch the content of a web resource that has already been indexed.

    Invoke this tool when:
     - the user requests analysis of resource content that has already been indexed, spidered or scanned
     - the user requests content with a URL that starts with "web://"

    Indexed JavaScript may be normalized, deobfuscated, or reconstructed from source maps for readability.
    Formatting, variable names, file paths, and line numbers may differ from code served by the target.
    Finding coordinates and source hashes refer to the analyzed artifact, not necessarily the deployed bundle.
    Prefer readable source for analysis; correlate artifact identity when validating behavior.
    Transformation may fail or be partial and does not guarantee faithful source recovery.
    Avoid repeating transformation unless the content warrants it.
    This waits briefly for relevant indexing, then reads the index without fetching the live URL.
    Null is a confirmed miss; a status-only indexing result means content may still be pending.
    Inspect indexing.potentially_incomplete before interpreting missing or partial results.
    When contents.has_more is true, request the next chunk with
    output_start_position=contents.offset + len(contents.text). Offsets count Unicode characters.
    This tool uses offsets rather than saved-page tokens.
    """
    await log_tool_history(ctx, "fetch_web_resource_content", url=url,
                           output_start_position=output_start_position, output_length_limit=output_length_limit)
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
            doc = await _find_document_by_type_and_id(doc_type, doc_id, metadata_only=True)
    else:
        try_http_url = True

    wait_url = doc.meta.get("url") if doc is not None else url
    opaque_id = doc_id if not try_http_url and doc is None else None
    indexing = await wait_for_indexing(
        ctx, server_ctx, url_matcher([wait_url], exact=True), doc_id=opaque_id,
        semantic=doc_type not in {None, "content", "network", "forms"},
    )
    if not try_http_url:
        doc = await _find_document_by_type_and_id(doc_type, doc_id)
    if try_http_url:
        filters = qm.Filter(must=[
            qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION)),
            qm.FieldCondition(key="meta.url", match=qm.MatchValue(value=url)),
        ])
        docs = await read_documents(server_ctx.qdrant_client, "content", filters, limit=1)
        if docs:
            logger.info("Found indexed web resource %s", url)
            doc = docs[0]
            doc_type = "content"
            doc_id = doc.id
    if not doc or not doc.content:
        if indexing.potentially_incomplete and indexing.status != "disabled":
            return IndexingOnlyResult(indexing=indexing)
        return None

    if output_start_position >= len(doc.content):
        text = ""
    else:
        text = doc.content[output_start_position:output_start_position + output_length_limit]

    logger.info("Returning %d/%d @ %d bytes for %s/%s", output_length_limit, len(doc.content), output_start_position,
                doc_type, doc_id)

    contents = TextResourcePartialContents(
        uri=str(url),
        mime_type=doc.meta.get('content_type', None),
        text=text,
        total_length=len(doc.content),
        offset=output_start_position,
        has_more=(output_start_position + output_length_limit < len(doc.content)),
    )
    result = IndexedResourceContent.from_doc(doc, contents=contents)
    result.indexing = indexing
    return result


@mcp_instance.resource("web://{doc_type}/{doc_id}", title="Web Resource")
async def web_resource(doc_type: str, doc_id: str) -> Optional[TextResourceContents]:
    """
    Fetch a document using the type and document ID.
    """
    doc: Document = await _find_document_by_type_and_id(doc_type, doc_id)
    if doc is None:
        return None
    return TextResourceContents(
        uri=f"web://{doc_type}/{doc_id}",
        mime_type=doc.meta.get('content_type', None),
        text=doc.content,
    )
