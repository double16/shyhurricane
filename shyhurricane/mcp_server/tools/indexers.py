import json
import logging
from datetime import datetime
from typing import Optional, Dict

import httpx
import persistqueue
import requests
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, TextResourceContents
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import Response

from shyhurricane.doc_type_model_map import map_mime_to_type
from shyhurricane.mcp_server import mcp_instance, get_server_context, log_tool_history, get_additional_hosts
from shyhurricane.mcp_server.tools.deobfuscate_javascript import deobfuscate_javascript
from shyhurricane.utils import stream_lines, is_katana_jsonl, is_http_csv_header, HttpResource, urlparse_ext, \
    extract_domain

logger = logging.getLogger(__name__)


@mcp_instance.custom_route('/index', methods=['POST'])
async def index_request_body(request: Request) -> Response:
    """
    Indexes HTTP one request/response to allow for further analysis. The input can take several
    forms. The preferred input format matches the output of the "katana" command for spidering.

    Example data argument in katana format:
    {"request": {"headers": {"sec_fetch_mode": "navigate", "priority": "u=0, i", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec_fetch_dest": "document", "host": "target.local", "accept_language": "en-US,en;q=0.5", "connection": "keep-alive", "sec_fetch_site": "none", "upgrade_insecure_requests": "1", "sec_fetch_user": "?1", "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}, "method": "GET", "source": "katana", "body": "", "endpoint": "https://target.local/", "tag": "katana", "attribute": "http"}, "response": {"headers": {"date": "Sun, 29 Jun 2025 03:44:52 GMT", "content_type": "text/html", "connection": "keep-alive", "location": "https://www.target.local/", "content_length": "169"}, "status_code": 301, "body": "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.20.1</center>\r\n</body>\r\n</html>\r\n"}, "timestamp": "2025-06-28T22:44:52.798000"}
    """
    server_ctx = await get_server_context()
    ingest_queue: persistqueue.SQLiteAckQueue = server_ctx.ingest_queue
    line_generator = stream_lines(request.stream())
    first = await anext(line_generator)
    if is_katana_jsonl(first):
        # each line is a request/response
        ingest_queue.put(first)
        async for line in line_generator:
            ingest_queue.put(line)
    elif is_http_csv_header(first):
        # each line is a request/response
        # TODO: map columns -> properties using "first"
        async for line in line_generator:
            # TODO: map csv to katana
            ingest_queue.put(line)
    else:
        # send entire body
        lines = [first]
        async for line in line_generator:
            lines.append(line)
        ingest_queue.put("\n".join(lines))

    return Response(status_code=201)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Index HTTP URL",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def index_http_url(
        ctx: Context,
        url: str,
        additional_hosts: Optional[Dict[str, str]] = None,
        method: str = "GET",
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        content: Optional[str] = None,
        follow_redirects: Optional[bool] = None,
) -> Optional[HttpResource]:
    """
    Index an HTTP URL to allow for further analysis and return the context, response code, response headers.

    Invoke this tool when the user needs the content of one specific URL.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.

    The request_headers map is extra request headers sent with the request.

    The cookies parameter is name, value pairs for cookies to send.

    The params is used to send either GET or POST parameters.

    The content is optional request body content.

    If follow_redirects is true, redirects will be followed and the result is the destination of the redirect.
    """
    await log_tool_history(ctx, "index_http_url",
                           url=url,
                           method=method,
                           user_agent=user_agent,
                           request_headers=request_headers,
                           cookies=cookies,
                           params=params,
                           follow_redirects=follow_redirects,
                           content=bool(content is not None),
                           additional_hosts=additional_hosts,
                           )
    server_ctx = await get_server_context()
    ingest_queue: persistqueue.SQLiteAckQueue = server_ctx.ingest_queue
    additional_hosts = get_additional_hosts(ctx, additional_hosts)
    if follow_redirects is None:
        follow_redirects = False
    the_headers = request_headers or {}
    if user_agent:
        the_headers['User-Agent'] = user_agent
    try:
        parsed_url = urlparse_ext(url)
        if parsed_url.hostname in additional_hosts:
            the_headers['Host'] = parsed_url.hostname
            munged_url = url.replace(f"://{parsed_url.hostname}", f"://{additional_hosts[parsed_url.hostname]}", 1)
            logger.info("Munged URL with additional hosts: %s", munged_url)
        else:
            munged_url = url
        async with httpx.AsyncClient() as client:
            response = await client.request(
                url=munged_url,
                method=method,
                headers=the_headers,
                cookies=cookies,
                params=params,
                content=content,
                follow_redirects=follow_redirects,
            )
        status_code = response.status_code
        response_headers = dict(response.headers)
        body = response.text

        ingest_queue.put(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "request": {
                "endpoint": url,
                "method": method,
                "headers": the_headers,
            },
            "response": {
                "status_code": status_code,
                "headers": response_headers,
                "body": body,
            }
        }))

        if map_mime_to_type(response.headers.get("Content-Type")) == "javascript":
            body = await deobfuscate_javascript(ctx, body)

        resource = TextResourceContents(
            uri=AnyUrl(url),
            mimeType=response.headers.get("Content-Type", ""),
            text=body,
        )
        return HttpResource(
            score=100,
            url=url,
            host=parsed_url.hostname,
            port=parsed_url.port,
            domain=extract_domain(parsed_url.hostname),
            status_code=status_code,
            method=method,
            resource=None,
            contents=resource,
            response_headers=response_headers,
        )
    except requests.exceptions.RequestException as e:
        logger.info("Request exception: %s", e)
        return None
