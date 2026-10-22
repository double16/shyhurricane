import json
import logging
import sqlite3
import subprocess
from datetime import datetime
from typing import Annotated, Any, Optional
from urllib.parse import urlencode

import httpx
import requests
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import TextResourceContents, ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.doc_type_model_map import map_mime_to_type
from shyhurricane.http_csv import http_csv_generator, is_http_csv
from shyhurricane.index.web_resources_pipeline import is_binary
from shyhurricane.mcp_server import (
    AdditionalHostsField,
    CookiesField,
    RequestHeadersField,
    RequestParamsField,
    UserAgentField,
    get_additional_hosts,
    get_additional_http_headers,
    get_server_context,
    log_tool_history,
    mcp_instance,
)
from shyhurricane.mcp_server.tools.deobfuscate_javascript import deobfuscate_javascript_full
from shyhurricane.result_pages import paged_content
from shyhurricane.utils import HttpResource, coerce_to_dict, extract_domain, is_katana_jsonl, stream_lines, urlparse_ext

logger = logging.getLogger(__name__)


def _request_mapping(value, name: str, kv_sep=None, element_sep=None) -> dict[str, str]:
    mapping = coerce_to_dict(value, kv_sep, element_sep)
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in mapping.items()
    ):
        raise ToolError(f"{name} must contain string names and string values")
    return mapping


def _serialize_request_body(body: str | dict[str, Any] | None, headers: dict[str, str]) -> str | None:
    if not isinstance(body, dict):
        return body
    content_type_header = next(
        (name for name in reversed(headers) if name.lower() == "content-type"), "Content-Type",
    )
    media_type = headers.get(content_type_header, "").split(";", 1)[0].strip().lower()
    try:
        if media_type.endswith("/json") or ("/" in media_type and media_type.endswith("+json")):
            return json.dumps(body, allow_nan=False)
        encoded = urlencode(body, doseq=True)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ToolError("request_body cannot be serialized for the request Content-Type") from error
    if not media_type:
        headers[content_type_header] = "application/x-www-form-urlencoded"
    return encoded


@mcp_instance.custom_route('/index', methods=['POST'])
async def index_request_body(request: Request) -> Response:
    """
    Indexes HTTP one request/response to allow for further analysis. The input can take several
    forms. The preferred input format matches the output of the "katana" command for spidering.

    Example data argument in katana format:
    {"request": {"headers": {"sec_fetch_mode": "navigate", "priority": "u=0, i", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec_fetch_dest": "document", "host": "target.local", "accept_language": "en-US,en;q=0.5", "connection": "keep-alive", "sec_fetch_site": "none", "upgrade_insecure_requests": "1", "sec_fetch_user": "?1", "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}, "method": "GET", "source": "katana", "body": "", "endpoint": "https://target.local/", "tag": "katana", "attribute": "http"}, "response": {"headers": {"date": "Sun, 29 Jun 2025 03:44:52 GMT", "content_type": "text/html", "connection": "keep-alive", "location": "https://www.target.local/", "content_length": "169"}, "status_code": 301, "body": "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.20.1</center>\r\n</body>\r\n</html>\r\n"}, "timestamp": "2025-06-28T22:44:52.798000"}
    """
    server_ctx = await get_server_context()
    line_generator = stream_lines(request.stream())
    first = await anext(line_generator, "")
    second = await anext(line_generator, "")
    if not first and not second:
        return Response(status_code=400)
    if is_katana_jsonl(first):
        logger.debug("Indexing katana JSONL")
        # each line is a request/response
        await server_ctx.enqueue_ingest(first)
        if second:
            await server_ctx.enqueue_ingest(second)
        async for line in line_generator:
            await server_ctx.enqueue_ingest(line)
    elif is_http_csv(first, second):
        logger.debug("Indexing CSV")
        # each line is a request/response
        # the csv library doesn't support async, so we need to collect everything first
        lines = [first]
        if second:
            lines.append(second)
        async for line in line_generator:
            lines.append(line)
        for rr in http_csv_generator(lines):
            await server_ctx.enqueue_ingest(rr.to_katana())
    else:
        logger.debug("Indexing entire body as single request")
        # send entire body
        lines = [first]
        if second:
            lines.append(second)
        async for line in line_generator:
            lines.append(line)
        await server_ctx.enqueue_ingest("\n".join(lines))

    return Response(status_code=201)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Index HTTP URL",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True),
)
@paged_content(
    "content_length_limit", "contents.text",
    save_failure_message=(
        "Response queued for ingestion, but unable to save preview pages. "
        "Repeating the call may enqueue the response again."
    ),
)
async def index_http_url(
        ctx: Context,
        url: str,
        additional_hosts: AdditionalHostsField = None,
        method: Annotated[str, Field("GET", description="The HTTP method to use")] = "GET",
        user_agent: UserAgentField = None,
        request_headers: RequestHeadersField = None,
        cookies: CookiesField = None,
        params: RequestParamsField = None,
        request_body: Annotated[
            str | dict[str, Any] | None,
            Field(description="Raw body text or a dictionary. Dictionaries use URL form encoding by default; "
                  "JSON request Content-Types use JSON serialization. Form lists use repeated keys."),
        ] = None,
        follow_redirects: Optional[bool] = None,
        content_length_limit: Annotated[
            int, Field(16384, description="Response preview characters per page", ge=1, le=4 * 1024 * 1024)
        ] = 16384,
) -> Optional[HttpResource]:
    """Fetch and index an HTTP URL for further analysis.

    Index an HTTP URL to allow for further analysis and return the context, response code, response headers.

    Invoke this tool when the user needs one URL. Text is indexed completely and returned as saved
    preview pages. Binary content returns metadata only. content_length_limit controls preview characters.

    Dictionary request bodies use URL form encoding unless the request Content-Type is JSON
    (such as application/json or application/problem+json). Missing or empty request Content-Type
    defaults to application/x-www-form-urlencoded for dictionaries. String bodies are sent as given.

    This contacts the live target; use fetch_web_resource_content for already indexed content.
    Indexing is asynchronous; the returned response may not be searchable immediately.
    Use get_result_page(pagination.next_page_token) for saved preview pages.
    A null next_page_token means there are no additional saved pages.
    follow_redirects defaults to false. Enable it only when redirect destinations are in scope.
    A null result indicates a request failure, not a successful empty response.
    Invalid inputs and queue failures raise tool errors. Missing Content-Type is treated as unknown.
    JavaScript command infrastructure failures return the original text. Preview storage errors
    can occur after queueing succeeds; repeating the call may enqueue the response again.
    """

    # coerce types
    additional_hosts = _request_mapping(additional_hosts, "additional_hosts")
    cookies = _request_mapping(cookies, "cookies", "=", ";")
    request_headers = _request_mapping(request_headers, "request_headers", ":", "\n")
    params = _request_mapping(params, "params", "=", "&")

    request_headers = get_additional_http_headers(ctx, request_headers)

    await log_tool_history(ctx, "index_http_url",
                           url=url,
                           method=method,
                           user_agent=user_agent,
                           request_headers=request_headers,
                           cookies=cookies,
                           params=params,
                           follow_redirects=follow_redirects,
                           request_body=bool(request_body is not None),
                           additional_hosts=additional_hosts,
                           )
    server_ctx = await get_server_context()
    if not server_ctx.open_world:
        raise ToolError("Network access has been disabled. Rely on indexed content.")

    try:
        parsed_url = urlparse_ext(url)
        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError("Unsupported scheme")
    except ValueError as error:
        raise ToolError("url must be a valid HTTP or HTTPS URL with a valid port") from error

    additional_hosts = get_additional_hosts(ctx, additional_hosts)
    if follow_redirects is None:
        follow_redirects = False
    the_headers = request_headers or {}
    if user_agent:
        the_headers['User-Agent'] = user_agent
    request_body = _serialize_request_body(request_body, the_headers)
    try:
        if parsed_url.hostname in additional_hosts:
            the_headers['Host'] = parsed_url.hostname
            munged_url = url.replace(f"://{parsed_url.hostname}", f"://{additional_hosts[parsed_url.hostname]}", 1)
            logger.debug("Munged URL with additional hosts: %s", munged_url)
        else:
            munged_url = url
        async with httpx.AsyncClient() as client:
            try:
                client.cookies.update(cookies)
                response = await client.request(
                    url=munged_url,
                    method=method,
                    headers=the_headers,
                    params=params,
                    content=request_body,
                    follow_redirects=follow_redirects,
                )
            except httpx.InvalidURL as error:
                raise ToolError("HTTP client rejected the request URL") from error
            except (TypeError, ValueError, UnicodeError) as error:
                raise ToolError("Invalid HTTP request inputs; check headers, cookies, parameters, and body") from error
        status_code = response.status_code
        response_headers = dict(response.headers)
        mime_type = response.headers.get("Content-Type", "")

        # Index complete textual content independently of the response preview size.
        body = None
        if not is_binary(None, mime_type):
            body = response.text

        ingest_item = json.dumps({
            "timestamp": datetime.now().isoformat(),
            "request": {
                "endpoint": url,
                "method": method,
                "headers": the_headers,
                "body": request_body,
            },
            "response": {
                "status_code": status_code,
                "headers": response_headers,
                "body": body,
            }
        })
        try:
            await server_ctx.enqueue_ingest(ingest_item)
        except (OSError, sqlite3.Error, RuntimeError) as error:
            logger.exception("Failed to queue fetched HTTP response")
            raise ToolError("Response fetched, but queueing for ingestion failed") from error

        if body and map_mime_to_type(mime_type) == "javascript":
            try:
                body = await deobfuscate_javascript_full(ctx, body)
            except (OSError, subprocess.SubprocessError):
                logger.exception("JavaScript transformation failed; returning original response text")

        if body:
            contents = TextResourceContents(
                uri=str(url),
                mime_type=mime_type,
                text=body,
            )
        else:
            contents = None
        return HttpResource(
            score=100,
            url=url,
            host=parsed_url.hostname,
            port=parsed_url.port,
            domain=extract_domain(parsed_url.hostname),
            status_code=status_code,
            method=method,
            resource=None,
            contents=contents,
            response_headers=response_headers,
        )
    except (httpx.RequestError, requests.exceptions.RequestException) as e:
        logger.info("Request exception: %s", e)
        return None
