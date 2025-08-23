import base64
import csv
import logging
import re
import sys
from typing import Optional, Generator

from shyhurricane.utils import urlparse_ext, parse_to_iso8601, parse_http_request, \
    parse_http_response
from shyhurricane.index.input_documents import IngestableRequestResponse

logger = logging.getLogger(__name__)


def is_http_csv(first: str, second: Optional[str]) -> bool:
    """
    Determine if this is a CSV, specifically something like Burp Suite's Logger++ CSV. The extension doesn't always
    emit a header, so we need to guess.
    """
    if first.strip():
        if ",Request." in first and ",Response." in first:
            return True
    if second is None or not second.strip():
        return False
    if second.replace(" ", "").startswith("{"):
        return False
    return second.count(",") >= 4


_http_header_key_re = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-zA-Z]+$")


def parse_headers(header_str: str) -> dict:
    headers = {}
    for line in header_str.strip().splitlines():
        if not line.strip() or ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()
        if not _http_header_key_re.match(key):
            raise ValueError(f"Invalid HTTP header field name: {key}")
        if key in headers:
            headers[key] += f", {value}"
        else:
            headers[key] = value
    return headers


def http_csv_generator(iterable) -> Generator[IngestableRequestResponse, None, None]:
    # Burp Logger++ does not always emit a header line so we're guessing
    csv.field_size_limit(sys.maxsize)
    reader = csv.reader(iterable)
    response_rtt_idx = None
    for row in reader:
        time = None
        url = None
        method = "GET"
        status_code = None
        request_headers = None
        request_body = None
        response_headers = None
        response_body = None
        response_rtt: Optional[float] = None

        for column_idx, column in enumerate(row):
            if len(column) == 0:
                continue
            if column == "Response.RTT":
                response_rtt_idx = column_idx
                continue

            if response_rtt_idx == column_idx:
                try:
                    response_rtt = float(column)
                except Exception:
                    pass
                continue

            if url is None and '://' in column and '\n' not in column:
                try:
                    urlparse_ext(column)
                    url = column.strip()
                    continue
                except Exception:
                    pass
            if time is None and len(column) < 40:
                try:
                    time, _ = parse_to_iso8601(column)
                    if time:
                        continue
                except Exception:
                    pass
            if method is None and " " not in column and len(column) < 30 and column == column.upper():
                method = column
                continue
            if status_code is None and len(column) == 3:
                try:
                    column_int = int(column)
                    if 100 <= column_int < 600:
                        status_code = column_int
                        continue
                except Exception:
                    pass

            try:
                headers = parse_headers(column)
                if len(headers) > 2:
                    if request_headers is None:
                        request_headers = headers
                        continue
                    else:
                        response_headers = headers
                        continue
            except Exception:
                pass

            if request_headers is None or request_body is None:
                try:
                    request_raw = base64.b64decode(column, validate=True).decode("utf-8")
                    parse_results = parse_http_request(request_raw)
                    if parse_results and parse_results[0] and parse_results[1] and parse_results[2] and parse_results[
                        3]:
                        method, _, _, request_headers, request_body, *_ = parse_results
                        continue
                except Exception:
                    pass

            if response_headers is None or response_body is None:
                try:
                    response_raw = base64.b64decode(column, validate=True).decode("utf-8")
                    parse_results = parse_http_response(response_raw)
                    if parse_results and parse_results[0] and parse_results[1]:
                        status_code, response_headers, response_body = parse_results
                        if not time and "Date" in response_headers:
                            try:
                                time, _ = parse_to_iso8601(response_headers["Date"])
                            except Exception:
                                pass
                        continue
                except Exception:
                    pass

        if url and method and request_headers and status_code and response_headers:
            yield IngestableRequestResponse(
                timestamp=time,
                url=url,
                method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                response_rtt=response_rtt,
                technologies=None,
                forms=None,
            )
