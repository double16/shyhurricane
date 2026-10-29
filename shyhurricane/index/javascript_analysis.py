"""Run source-map recovery and Opengrep for indexed JavaScript."""

import hashlib
import io
import json
import logging
import subprocess
import tarfile

import httpx as httpx
from haystack import Document

from shyhurricane.doc_type_model_map import map_mime_to_type
from shyhurricane.finding_metadata import scanner_metadata
from shyhurricane.graph.artifacts import recovered_sources
from shyhurricane.source_maps import MAX_SOURCE_MAP_BYTES as MAX_SOURCE_MAP_BYTES
from shyhurricane.source_maps import _cached_map, _fetch_map, _valid_map, javascript_url_from_map, source_map_url
from shyhurricane.task_queue.types import SaveFindingQueueItem
from shyhurricane.utils import unix_command_image

logger = logging.getLogger(__name__)

MAX_JAVASCRIPT_BYTES = 40 * 1024 * 1024


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
    cwes = (extra.get("metadata") or {}).get("cwe") or []
    metadata = scanner_metadata("opengrep", rule, severity, cwes=cwes if isinstance(cwes, list) else [cwes])
    metadata["code_location"] = {
        "source_path": source_path, "start_line": line,
        "coordinate_space": "recovered" if map_used else "delivered",
    }
    return SaveFindingQueueItem(target=url, markdown=markdown, title=title, finding_id=key, metadata=metadata)


def analyze_document(doc: Document, open_world: bool, content_store, finding_queue, artifacts=None) -> int:
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
        if artifacts is not None:
            source_map = artifacts.source_map(url, source, json.loads(doc.meta.get("request_headers", "{}")),
                                              open_world, content_store, doc.meta.get("content_sha256"),
                                              json.loads(doc.meta.get("response_headers", "{}")))
        else:
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
    recovered = dict(recovered_sources(source_map)) if source_map else {}
    count = 0
    for match in result.get("results", []):
        finding = _finding(target_url, match, source_map is not None)
        if finding is not None:
            if not source_map and source:
                finding.metadata["content_sha256"] = hashlib.sha256(source.encode()).hexdigest()
            elif source_map:
                source_path = finding.metadata["code_location"]["source_path"]
                if source_path in recovered:
                    finding.metadata["content_sha256"] = hashlib.sha256(recovered[source_path].encode()).hexdigest()
            finding_queue.put(finding)
            count += 1
    return count
