#!/usr/bin/env python3
import argparse
import base64
import csv
import json
import re
import sys
from typing import Optional
from urllib.parse import urlparse

import requests

from shyhurricane.utils import parse_http_request, parse_http_response, parse_to_iso8601

# ─── Argument Parser ───────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Queue request-responses for indexing.")
parser.add_argument("--mcp-url", default="http://127.0.0.1:8000/", required=True,
                    help="URL for the MCP server, i.e. http://127.0.0.1:8000/")
parser.add_argument("--katana", action="store_true", help="Read katana jsonl")
parser.add_argument("--csv", action="store_true", help="Read Burp Logger++ CSV")
args = parser.parse_args()

if not args.katana and not args.csv:
    sys.exit("You need to specify either --katana or --csv")

# ─── Process stdin line-by-line ───────────────────────────────────────

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


if args.mcp_url.endswith("/"):
    index_url = args.mcp_url + "index"
else:
    index_url = args.mcp_url + "/index"

try:
    requests.post(index_url, data="{}").raise_for_status()
    print(f"[✔] {index_url} verified", file=sys.stderr)
except Exception as e:
    print(f"[✘] Error: {index_url}, {e}", file=sys.stderr)
    sys.exit(1)

if args.katana:
    for line in sys.stdin:
        try:
            url = str(json.loads(line).get('request', {}).get('endpoint'))
        except Exception:
            continue
        try:
            requests.post(index_url, data=line.strip()).raise_for_status()
            print(f"[✔] Queued for indexing: {url}", file=sys.stderr)
        except Exception as e:
            print(f"[✘] Error: {url}, {e}", file=sys.stderr)
            continue

# TODO: move to /index endpoint
elif args.csv:
    # Burp Logger++ does not always emit a header line so we're guessing
    csv.field_size_limit(sys.maxsize)
    reader = csv.reader(sys.stdin)
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

            if url is None and '://' in column and not '\n' in column:
                try:
                    urlparse(column)
                    url = column
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
                        method, _, _, request_headers, request_body = parse_results
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
            json_payload = json.dumps({
                "timestamp": time,
                "request": {
                    "endpoint": url,
                    "method": method,
                    "headers": request_headers,
                    "body": request_body,
                },
                "response": {
                    "status_code": status_code,
                    "headers": response_headers,
                    "body": response_body,
                    "rtt": response_rtt,
                }
            })
            try:
                requests.post(index_url, data=json_payload).raise_for_status()
                print(f"[✔] Queued for indexing: {url}", file=sys.stderr)
            except Exception as e:
                print(f"[✘] Error: {url}, {e}", file=sys.stderr)
                continue
