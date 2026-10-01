"""Run source-map recovery and Opengrep for indexed JavaScript."""

import hashlib
import io
import json
import logging
import subprocess
import tarfile
from urllib.parse import urlsplit, urlunsplit

import httpx
from haystack import Document

from shyhurricane.doc_type_model_map import map_mime_to_type
from shyhurricane.task_queue.types import SaveFindingQueueItem
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)

MAX_SOURCE_MAP_BYTES = 40 * 1024 * 1024
MAX_JAVASCRIPT_BYTES = 40 * 1024 * 1024


def source_map_url(javascript_url: str) -> str | None:
    parsed = urlsplit(javascript_url)
    if parsed.scheme not in {"http", "https"} or not parsed.path.lower().endswith(".js"):
        return None
    return urlunsplit(parsed._replace(path=f"{parsed.path}.map"))


def javascript_url_from_map(map_url: str) -> str | None:
    parsed = urlsplit(map_url)
    if not parsed.path.lower().endswith(".js.map"):
        return None
    return urlunsplit(parsed._replace(path=parsed.path[:-4]))


def _cached_map(store, map_url: str) -> str | None:
    if store is None:
        return None
    docs = store.filter_documents(filters={"field": "meta.url", "operator": "==", "value": map_url})
    eligible = [doc for doc in docs if doc.content and len(doc.content.encode("utf-8")) <= MAX_SOURCE_MAP_BYTES]
    if not eligible:
        return None

    def timestamp(doc: Document) -> float:
        value = doc.meta.get("timestamp_float")
        return value if isinstance(value, (int, float)) else float("-inf")

    return max(eligible, key=timestamp).content


def _fetch_map(map_url: str, request_headers: dict) -> str | None:
    headers = {key: value for key, value in request_headers.items()
               if key.lower() in {"authorization", "cookie", "user-agent"}}
    try:
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            with client.stream("GET", map_url, headers=headers) as response:
                if response.status_code != 200:
                    return None
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_SOURCE_MAP_BYTES:
                        return None
        return data.decode("utf-8")
    except (httpx.HTTPError, UnicodeDecodeError) as exc:
        logger.info("Source map request failed for %s: %s", map_url, exc)
        return None


def _valid_map(content: str | None) -> bool:
    if not content:
        return False
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and data.get("version") == 3 and isinstance(data.get("sources"), list)


def _run_opengrep(source: str, source_map: str | None) -> dict | None:
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        for name, content in (("source.js", source), ("source.js.map", source_map)):
            if content is None:
                continue
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    command = ["docker", "run", "--rm", "-i",
               "-v", "shyhurricane_opengrep_rules:/opt/opengrep-rules",
               unix_command_image(), "/usr/local/bin/scan_javascript.sh"]
    try:
        result = subprocess.run(command, input=archive_buffer.getvalue(), capture_output=True,
                                timeout=240, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("JavaScript scan failed: %s", exc)
        return None
    if result.returncode != 0:
        logger.warning("JavaScript scan exited %d: %s", result.returncode,
                       result.stderr.decode(errors="replace")[-500:])
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("JavaScript scan returned invalid JSON")
        return None


def _finding(url: str, match: dict, map_used: bool) -> SaveFindingQueueItem | None:
    extra = match.get("extra") or {}
    start = match.get("start") or {}
    rule = match.get("check_id")
    path = match.get("path")
    line = start.get("line")
    if not rule or not path or not isinstance(line, int):
        return None
    source_path = path.removeprefix("/work/scan/").removeprefix("work/")
    message = str(extra.get("message") or rule)
    severity = str(extra.get("severity") or "INFO")
    evidence = str(extra.get("lines") or "").strip()[:1000]
    key = hashlib.sha256(f"{url}\0{source_path}\0{rule}\0{line}\0{evidence}".encode()).hexdigest()
    title = f"Opengrep: {message[:90]}"
    markdown = (
        f"# {title}\n\n"
        f"## Issue Summary\n{message}\n\n"
        f"## Discovery Method\nOpengrep rule `{rule}` ({severity}) scanned "
        f"{'source-map source' if map_used else 'JavaScript'} from {url}.\n\n"
        f"## Reproduction Steps\nInspect `{source_path}` at line {line} in the indexed resource.\n\n"
        f"## PoC\n```javascript\n{evidence}\n```\n\n"
        "## Fix\nReview the matched code and apply the rule's recommended remediation.\n\n"
        f"## References\nOpengrep rule `{rule}`.\n"
    )
    return SaveFindingQueueItem(target=url, markdown=markdown, title=title, finding_id=key)


def analyze_document(doc: Document, open_world: bool, content_store, finding_queue) -> int:
    """Analyze one indexed JS or JS source map document and queue matching findings."""
    url = doc.meta.get("url", "")
    source = doc.content or ""
    if not source or len(source.encode("utf-8")) > MAX_JAVASCRIPT_BYTES:
        return 0
    map_url = javascript_url_from_map(url)
    if map_url:
        target_url = map_url
        source_map = source
        source = ""
    elif map_mime_to_type(doc.meta.get("content_type", "")) == "javascript" or source_map_url(url):
        target_url = url
        map_url = source_map_url(url)
        source_map = _cached_map(content_store, map_url) if map_url else None
        if source_map is None and map_url and open_world:
            source_map = _fetch_map(map_url, json.loads(doc.meta.get("request_headers", "{}")))
    else:
        return 0

    if not _valid_map(source_map):
        source_map = None
    if not source and not source_map:
        return 0
    result = _run_opengrep(source, source_map)
    if result is None:
        return 0
    count = 0
    for match in result.get("results", []):
        finding = _finding(target_url, match, source_map is not None)
        if finding is not None:
            finding_queue.put(finding)
            count += 1
    return count
