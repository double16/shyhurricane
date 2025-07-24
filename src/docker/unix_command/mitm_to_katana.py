import argparse
import datetime
import json
import sys

from mitmproxy import http

# Parse args early since mitmdump loads this as a module
parser = argparse.ArgumentParser(description="Log HTTP request/response as JSON")
parser.add_argument(
    "--ignore",
    type=str,
    default="404,429,503",
    help="Comma-separated list of response status codes to ignore (default: 404,429,503)"
)

# Only parse known args to avoid conflict with mitmdump's args
args, _ = parser.parse_known_args(sys.argv)

# Convert to int set
ignored_codes = set(int(code.strip()) for code in args.ignore.split(",") if code.strip().isdigit())


def response(flow: http.HTTPFlow) -> None:
    if flow.response.status_code in ignored_codes:
        return

    entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.url,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text(),
        },
        "response": {
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.get_text(),
        }
    }
    if flow.response.timestamp_end and flow.response.timestamp_start:
        entry["response"]["rtt"] = (flow.response.timestamp_end - flow.response.timestamp_start) * 1000.0

    print(json.dumps(entry), flush=True)
