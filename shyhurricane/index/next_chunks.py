"""Retrieve explicitly declared Next.js assets through the durable ingest queue."""

import json
import logging
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from shyhurricane.graph.extract import extract, run_javascript
from shyhurricane.graph.model import capture_event, identity

logger = logging.getLogger(__name__)
TASK = "_next_chunk_fetch"
MAX_BYTES = 40 * 1024 * 1024


def schedule(artifacts, queue, response):
    """Coalesce declarations by source capture and URL before queue delivery."""
    event = capture_event(response)
    path = urlsplit(response.url).path
    headers = {key.lower(): value for key, value in response.response_headers.items()}
    mime = headers.get("content-type", "").split(";")[0].strip().lower()
    if not (path.endswith("/_buildManifest.js") or mime in {"text/html", "text/x-component"}):
        return
    if not response.response_body or len(response.response_body.encode()) > 1024 * 1024:
        return
    runner = run_javascript if path.endswith("/_buildManifest.js") else lambda *_: {}
    try:
        graph = extract(event, javascript_runner=runner)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        logger.info("Next.js chunk discovery failed for %s: %s", response.url, exc)
        return
    urls = {
        graph.nodes[edge["target"]]["url"]
        for edge in graph.edges.values()
        if graph.evidence[edge["evidence_id"]]["rule"] in {
            "next.pages-manifest", "next.flight-import", "next.flight-module-chunk",
        }
    }
    artifacts.connection.execute(
        "CREATE TABLE IF NOT EXISTS next_chunk_delivery (id TEXT PRIMARY KEY, delivered INTEGER NOT NULL)"
    )
    artifacts.connection.commit()
    modules_by_url = {}
    for edge in graph.edges.values():
        node = graph.nodes[edge["source"]]
        if node["kind"] == "module_reference":
            url = graph.nodes[edge["target"]].get("url")
            modules_by_url.setdefault(url, []).append(node)
    for url in sorted(urls):
        module_references = modules_by_url.get(url, [])
        key = identity(event["id"], url)
        with artifacts.lock("next-chunk-delivery"):
            with artifacts.connection:
                artifacts.connection.execute("INSERT OR IGNORE INTO next_chunk_delivery VALUES (?,0)", (key,))
            row = artifacts.connection.execute(
                "SELECT delivered FROM next_chunk_delivery WHERE id=?", (key,),
            ).fetchone()
            if row[0]:
                continue
            queue.put(json.dumps({TASK: {
                "url": url, "declaring_capture": event["id"], "observed_at": event["observed_at"],
                "module_references": [
                    {"id": node["id"], "module_id": node["bundle_module_id"]}
                    for node in module_references
                ],
            }}))
            with artifacts.connection:
                artifacts.connection.execute("UPDATE next_chunk_delivery SET delivered=1 WHERE id=?", (key,))


def fetch_task(item, *, open_world, artifacts):
    """Return a normal Katana exchange for a queued task, or None when skipped."""
    data = json.loads(item)
    if TASK not in data:
        return item
    if not open_world:
        return None
    task = data[TASK]
    url = task["url"]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    if "/_next/static/chunks/" not in parsed.path or not parsed.path.endswith(".js"):
        return None
    with artifacts.lock("next-chunk-" + identity(url)):
        existing = artifacts.latest(url)
        if (existing and existing["observed_at"] >= task.get("observed_at", float("-inf"))
                and existing["data"].get("method") == "GET"
                and existing["data"].get("response_code") == 200 and existing["data"].get("response_body")):
            return None
        try:
            with httpx.Client(timeout=5, follow_redirects=False, verify=False) as client:
                with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        logger.info("Next.js chunk request for %s returned %s", url, response.status_code)
                        return None
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > MAX_BYTES:
                            logger.info("Next.js chunk exceeds response limit: %s", url)
                            return None
                        body.extend(chunk)
                    text = body.decode("utf-8")
                    headers = dict(response.headers)
        except (httpx.HTTPError, UnicodeDecodeError) as exc:
            logger.info("Next.js chunk retrieval failed for %s: %s", url, exc)
            return None
    return json.dumps({
        "capture_provenance": {
            "kind": "next_manifest_fetch", "declaring_capture": task["declaring_capture"],
            "module_references": json.dumps(task.get("module_references", [])),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": {"endpoint": url, "method": "GET", "headers": {}, "body": None},
        "response": {"status_code": 200, "headers": headers, "body": text},
    })
