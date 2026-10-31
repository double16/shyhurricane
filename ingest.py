#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Optional

import requests

from shyhurricane.burp_issues_xml import burp_xml_records
from shyhurricane.http_csv import http_csv_generator


def _post(index_url: str, payload: str, url: str, content_type: Optional[str] = None) -> None:
    try:
        headers = dict()
        if content_type:
            headers["Content-Type"] = content_type
        requests.post(index_url, data=payload, headers=headers).raise_for_status()
        action = "finding" if index_url.endswith("/findings") else "indexing"
        print(f"[✔] Queued for {action}: {url}", file=sys.stderr)
    except Exception as error:
        print(f"[✘] Error: {url}, {error}", file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Queue request-responses for indexing.")
    parser.add_argument("--mcp-url", default="http://127.0.0.1:8000/", required=True,
                        help="URL for the MCP server, i.e. http://127.0.0.1:8000/")
    parser.add_argument("--katana", action="store_true", help="Read katana jsonl")
    parser.add_argument(
        "--csv", action="store_true",
        help="Read Burp Logger++ CSV (fields: Request.AsBase64, Request.Time, Request.URL, Response.AsBase64)",
    )
    parser.add_argument("--burp-xml", action="store_true", help="Read Burp Suite request/response or issues XML export")
    args = parser.parse_args(argv)
    if not args.katana and not args.csv and not args.burp_xml:
        parser.error("You need to specify --katana, --csv or --burp-xml")
    if args.burp_xml and (args.katana or args.csv):
        parser.error("--burp-xml cannot be combined with --katana or --csv")
    index_url = args.mcp_url.rstrip("/") + "/index"
    findings_url = args.mcp_url.rstrip("/") + "/findings"
    try:
        requests.post(index_url, data="{}").raise_for_status()
        print(f"[✔] {index_url} verified", file=sys.stderr)
    except Exception as error:
        print(f"[✘] Error: {index_url}, {error}", file=sys.stderr)
        return 1

    if args.katana:
        for line in sys.stdin:
            try:
                payload = json.loads(line)
                if "request" in payload:
                    url = str(payload.get("request", {}).get("endpoint"))
                    _post(index_url, line.strip(), url)
                elif "target" in payload and "title" in payload and "markdown" in payload:
                    _post(findings_url, line.strip(), payload["target"], "application/json")
            except Exception:
                continue
    else:
        try:
            records = (
                burp_xml_records(sys.stdin.buffer) if args.burp_xml else
                (("exchange", record) for record in http_csv_generator(sys.stdin))
            )
            for kind, record in records:
                if kind == "finding":
                    _post(findings_url, json.dumps(record), record["target"], "application/json")
                else:
                    _post(index_url, record.to_katana(), record.url)
        except Exception as error:
            print(f"[✘] Error reading input: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
