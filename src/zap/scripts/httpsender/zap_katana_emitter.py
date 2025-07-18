# ZAP httpsender script — emits Katana‑style JSONL
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

import json, datetime, java.io
from org.parosproxy.paros.network import HttpMessage

# ─── configure output file ─────────────────────────────
LOG_PATH = "/tmp/zap_katana.jsonl"  # change as required
# global writer (append)
try:
    _writer = java.io.BufferedWriter(java.io.FileWriter(LOG_PATH, True))
except Exception as _e:
    print("[zap script] cannot open log file:", _e)
    _writer = None


# ─── utility ───────────────────────────────────────────────────

def to_headers(java_headers):
    """Return lower‑cased header map from ZAP header object."""
    h = {}
    for header in java_headers.getHeaders():
        name = header.getName()
        h[name.lower().replace('-', '_')] = java_headers.getHeader(name)
    return h


SKIP_PREFIXES = ("audio/", "video/", "font/")


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
    if ct == 'application/octet-stream':
        return True
    return False


# ─── ZAP callbacks ────────────────────────────────────────────

def sendingRequest(msg, initiator, helper):
    pass  # only care after response


def responseReceived(msg, initiator, helper):
    try:
        req_hdr = msg.getRequestHeader()
        res_hdr = msg.getResponseHeader()

        ctype = res_hdr.getHeader("Content-Type") or res_hdr.getHeader("content-type") or ""
        if should_skip(ctype):
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
                "body": msg.getResponseBody().toString()
            }
        }

        if _writer:
            _writer.write(json.dumps(entry) + "\n")
            _writer.flush()
    except Exception as e:
        print("[zap script] serialisation error:", e)
