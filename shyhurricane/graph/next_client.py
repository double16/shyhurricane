"""Bounded extraction of explicitly named assets in browser-visible Flight records."""

import json
import re

_INLINE = re.compile(r"(?:self\.__next_f|\(self\.__next_f=self\.__next_f\|\|\[\]\))\.push\((.*)\);?\s*\Z", re.S)
_LENGTH_PREFIX = re.compile(r"[0-9a-f]+:[TAOoUSsLlGgMmV][0-9a-f]+,")
_ROW = re.compile(r"([0-9a-f]+):(.*)\Z")
_OUTLINED = re.compile(r'"((?:/_next/)?static/chunks/[a-zA-Z0-9_./-]+\.js)"\s*\Z')
_OUTLINED_ID = re.compile(r"\$([0-9a-f]+)\Z")
_CHUNK = re.compile(r"(?:/_next/)?static/chunks/[a-zA-Z0-9_./%-]+\.js\Z")
_MAX_BYTES = 1024 * 1024
_MAX_ROWS = 10_000


def inline_flight(script):
    """Return a literal type-1 bootstrap fragment, or None for ordinary scripts."""
    if "__next_f" not in script or len(script.encode()) > _MAX_BYTES:
        return None
    match = _INLINE.fullmatch(script.strip())
    if not match:
        return None
    try:
        record = json.loads(match[1])
    except (ValueError, RecursionError):
        return None
    if isinstance(record, list) and len(record) == 2 and record[0] == 1 and isinstance(record[1], str):
        return record[1]
    return None


def flight_assets(body, emit, gaps, location):
    """Project only import rows with explicit, local Next.js chunk paths."""
    if len(body.encode(errors="surrogatepass")) > _MAX_BYTES or body.count("\n") > _MAX_ROWS:
        gaps.append("Next.js Flight analysis budget reached")
        return
    unsupported = False
    lines = body.split("\n")
    if lines.pop():
        gaps.append("Next.js Flight response ends in an incomplete row")
    outlined = {}
    imports = []
    for index, line in enumerate(lines, 1):
        if _LENGTH_PREFIX.match(line):
            gaps.append("Unsupported length-prefixed Next.js Flight record")
            break
        row = _ROW.fullmatch(line)
        if not row:
            continue
        key, payload = row.groups()
        chunk = _OUTLINED.fullmatch(payload)
        outlined[key] = chunk[1] if chunk and key not in outlined else None
        if payload.startswith("I"):
            imports.append((index, payload[1:]))
    for index, payload in imports:
        try:
            record = json.loads(payload)
        except (ValueError, RecursionError):
            unsupported = True
            continue
        if not isinstance(record, list) or len(record) < 3 or not isinstance(record[1], list):
            unsupported = True
            continue
        for value in record[1]:
            if not isinstance(value, str):
                continue
            key = _OUTLINED_ID.fullmatch(value)
            if key:
                value = outlined.get(key[1])
                if value is None:
                    unsupported = True
                    continue
            if _CHUNK.fullmatch(value) and ".." not in value and "%" not in value:
                path = value if value.startswith("/") else f"/_next/{value}"
                module_id, export_name = record[0], record[2]
                emit(path, module_id, export_name, f"{location}:{index}")
    if unsupported:
        gaps.append("Unsupported Next.js Flight import record")
