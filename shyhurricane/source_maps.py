"""Lightweight source-map lookup helpers shared by indexing and graph parsing."""

import json
import logging
from urllib.parse import urlsplit, urlunsplit

import httpx

logger = logging.getLogger(__name__)
MAX_SOURCE_MAP_BYTES = 40 * 1024 * 1024


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

    def timestamp(doc) -> float:
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


