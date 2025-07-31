# ZAP shyhurricane httpsender script — posts Katana‑style JSONL to the shyhurricane /index endpoint
# Target: "response" (fires after full HTTP exchange)
# Engine: Jython

"""
Output example (one line):
{
  "timestamp": "2024-07-24T08:25:28.876868-05:00",
  "request": {
    "method": "GET",
    "endpoint": "https://example.com/index.html",
    "tag": "link",
    "attribute": "href",
    "source": "https://example.com/robots.txt",
    "headers": {"user-agent": "Mozilla/5.0", ...},
    "body": ""
  },
  "response": {
    "status_code": 200,
    "headers": {"content_type": "text/html", ...},
    "body": "<!doctype html>..."
  }
}
"""

import datetime
import json

import java.io
from org.apache.commons.httpclient import URI
from java.lang import String
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader, HttpHeader, HttpSender

MCP_URI = URI("http://127.0.0.1:8001/index")

def to_headers(java_headers):
    """Return lower‑cased header map from ZAP header object."""
    h = {}
    for header in java_headers.getHeaders():
        name = header.getName()
        h[name.lower().replace('-', '_')] = java_headers.getHeader(name)
    return h


SKIP_PREFIXES = ("audio/", "video/", "font/", "binary/")


def should_skip(content_type):
    if not content_type:
        return False
    ct = content_type.lower()
    if "+json" in ct or "+xml" in ct:
        return False
    if ct.startswith(SKIP_PREFIXES):
        return True
    if ct.startswith("image/") and "svg" not in ct:
        return True
    if ct in [
        "application/octet-stream",
        "application/pdf",
        "application/x-pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/x-protobuf",
        "application/font-woff",
        "application/font-woff2",
        "application/vnd.ms-fontobject",
    ]:
        return True
    return False

def sendingRequest(msg, initiator, helper):
    pass  # only care after response


def responseReceived(msg, initiator, helper):
    try:
        if not msg.isInScope():
            return

        req_hdr = msg.getRequestHeader()
        res_hdr = msg.getResponseHeader()

        ctype = res_hdr.getHeader("Content-Type") or res_hdr.getHeader("content-type") or ""
        if should_skip(ctype):
            print("Skip indexing of "+str(req_hdr.getURI()))
            return  # ignore binary assets

        now = datetime.datetime.now().isoformat()

        entry = {
            "timestamp": now,
            "request": {
                "method": req_hdr.getMethod(),
                "endpoint": str(req_hdr.getURI()),
                "tag": "zap",
                "attribute": "http",
                "source": "zap-proxy",
                "headers": to_headers(req_hdr),
                "body": msg.getRequestBody().toString()
            },
            "response": {
                "status_code": res_hdr.getStatusCode(),
                "headers": to_headers(res_hdr),
                "body": msg.getResponseBody().toString(),
                "rtt": float(msg.getTimeElapsedMillis()) / 1000.0,
            }
        }

        print("Indexing "+str(req_hdr.getURI()))

        payload = json.dumps(entry)
        header = HttpRequestHeader(HttpRequestHeader.POST, MCP_URI, HttpHeader.HTTP11)
        header.setHeader(HttpHeader.CONTENT_TYPE, "application/json")
        message = HttpMessage()
        message.setRequestHeader(header)
        message.setRequestBody(String(payload))
        header.setContentLength(len(payload))

        sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
        sender.sendAndReceive(message, False)
    except Exception as e:
        print("[zap script] serialisation error:", e)
