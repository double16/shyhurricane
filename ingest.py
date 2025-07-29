#!/usr/bin/env python3
import argparse
import json
import sys

import requests

from shyhurricane.http_csv import http_csv_generator

# ─── Argument Parser ───────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Queue request-responses for indexing.")
parser.add_argument("--mcp-url", default="http://127.0.0.1:8000/", required=True,
                    help="URL for the MCP server, i.e. http://127.0.0.1:8000/")
parser.add_argument("--katana", action="store_true", help="Read katana jsonl")
parser.add_argument("--csv", action="store_true", help="Read Burp Logger++ CSV")
args = parser.parse_args()

if not args.katana and not args.csv:
    sys.exit("You need to specify either --katana or --csv")

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

elif args.csv:
    for rr in http_csv_generator(sys.stdin):
        json_payload = rr.to_katana()
        try:
            requests.post(index_url, data=json_payload).raise_for_status()
            print(f"[✔] Queued for indexing: {rr.url}", file=sys.stderr)
        except Exception as e:
            print(f"[✘] Error: {rr.url}, {e}", file=sys.stderr)
            continue
