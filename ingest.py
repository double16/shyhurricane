#!/usr/bin/env python3
import argparse
import base64
import csv
import datetime
import json
import re
import sys
from urllib.parse import urlparse
from typing import Optional
from zoneinfo import ZoneInfo

from ingest_queue import get_ingest_queue
from utils import parse_http_request, parse_http_response

# ─── Argument Parser ───────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Queue request-responses for indexing.")
parser.add_argument("--db", "-d", default="127.0.0.1:8200", help="Chroma location, host:port")
parser.add_argument("--katana", action="store_true", help="Read katana jsonl")
parser.add_argument("--csv", action="store_true", help="Read Burp Logger++ CSV")
args = parser.parse_args()

if not args.katana and not args.csv:
    sys.exit("You need to specify either --katana or --csv")

# ─── Process stdin line-by-line ───────────────────────────────────────
ingest_queue = get_ingest_queue(db=args.db)

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


def parse_to_iso8601(timestr: str) -> str:
    # Maps timezone abbreviations to IANA timezone names
    tz_abbrev_to_iana = {
        "CDT": "America/Chicago",
        "CST": "America/Chicago",
        "EDT": "America/New_York",
        "EST": "America/New_York",
        "MDT": "America/Denver",
        "MST": "America/Denver",
        "PDT": "America/Los_Angeles",
        "PST": "America/Los_Angeles",
        "GMT": "UTC",
        "UTC": "UTC",
    }

    # Try format 1: "Sat Jul 19 08:23:11 CDT 2025"
    m1 = re.match(r"^(\w{3}) (\w{3}) (\d{1,2}) (\d{2}:\d{2}:\d{2}) (\w{3}) (\d{4})$", timestr)
    if m1:
        _, month, day, time_str, tz_abbrev, year = m1.groups()
        tz = ZoneInfo(tz_abbrev_to_iana[tz_abbrev])
        dt = datetime.datetime.strptime(f"{month} {day} {year} {time_str}", "%b %d %Y %H:%M:%S")
        return dt.replace(tzinfo=tz).isoformat()

    # Try format 2: "Sat, 19 Jul 2025 13:23:10 GMT"
    m2 = re.match(r"^\w{3}, (\d{1,2}) (\w{3}) (\d{4}) (\d{2}:\d{2}:\d{2}) (\w{3})$", timestr)
    if m2:
        day, month, year, time_str, tz_abbrev = m2.groups()
        tz = ZoneInfo(tz_abbrev_to_iana[tz_abbrev])
        dt = datetime.datetime.strptime(f"{day} {month} {year} {time_str}", "%d %b %Y %H:%M:%S")
        return dt.replace(tzinfo=tz).isoformat()

    raise ValueError(f"Unrecognized time format: {timestr}")


if args.katana:
    for line in sys.stdin:
        try:
            url = str(json.loads(line).get('request', {}).get('endpoint', '???'))
        except Exception:
            continue
        try:
            ingest_queue.put(line.strip())
            print(f"[✔] Queued for indexing: {url}", file=sys.stderr)
        except Exception as e:
            print(f"[✘] Error: {url}, {e}", file=sys.stderr)
            continue

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
                    time = parse_to_iso8601(column)
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
                                time = parse_to_iso8601(response_headers["Date"])
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
                ingest_queue.put(json_payload)
                print(f"[✔] Queued for indexing: {url}", file=sys.stderr)
            except Exception as e:
                print(f"[✘] Error: {url}, {e}", file=sys.stderr)
                continue
