"""Read Burp Suite request/response XML exports without resolving XML entities."""

import base64
import sys
from collections.abc import Generator
from typing import BinaryIO

from lxml import etree

from shyhurricane.index.input_documents import IngestableRequestResponse
from shyhurricane.utils import parse_http_request, parse_http_response, parse_to_iso8601, urlparse_ext


def _http_text(item: etree._Element, name: str) -> str:
    element = item.find(name)
    if element is None or len(element):
        raise ValueError(f"Missing {name} or unsupported XML entity")
    text = element.text or ""
    encoding = element.get("base64", "false")
    if encoding == "true":
        return base64.b64decode("".join(text.split()), validate=True).decode("utf-8", errors="replace")
    if encoding != "false":
        raise ValueError(f"Invalid base64 attribute for {name}")
    return text


def _parse_item(item: etree._Element) -> IngestableRequestResponse:
    if any(isinstance(element, etree._Entity) for element in item.iter()):
        raise ValueError("Unsupported XML entity")
    url = (item.findtext("url") or "").strip()
    urlparse_ext(url)
    timestamp, _ = parse_to_iso8601((item.findtext("time") or "").strip())
    method, path, version, request_headers, request_body, _ = parse_http_request(_http_text(item, "request"))
    status, response_headers, response_body = parse_http_response(_http_text(item, "response"))
    if not method or not path or not version or not version.startswith("HTTP/"):
        raise ValueError("Invalid HTTP request line")
    if status is None or not 100 <= status < 600:
        raise ValueError("Invalid HTTP response status")
    return IngestableRequestResponse(
        url=url, timestamp=timestamp, method=method,
        request_headers=request_headers, request_body=request_body,
        response_code=status, response_headers=response_headers, response_body=response_body,
        response_rtt=None, technologies=None, forms=None,
    )


def http_burp_xml_generator(source: BinaryIO) -> Generator[IngestableRequestResponse, None, None]:
    """Yield valid items, reporting bad records; invalid XML raises an exception."""
    context = etree.iterparse(
        source, events=("start", "end"), resolve_entities=False, load_dtd=False, no_network=True
    )
    root = None
    item_number = 0
    for event, element in context:
        if root is None:
            root = element
            if root.tag != "items":
                raise ValueError("Expected Burp XML root <items>")
        if event != "end" or element.tag != "item" or element.getparent() is not root:
            continue
        item_number += 1
        try:
            yield _parse_item(element)
        except (ValueError, KeyError, TypeError) as error:
            print(f"[✘] Skipping XML item {item_number}: {error}", file=sys.stderr)
        finally:
            element.clear()
            while element.getprevious() is not None:
                del root[0]
