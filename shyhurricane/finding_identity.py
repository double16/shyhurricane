"""Conservative identities and cross-process serialization for finding saves."""

import fcntl
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from shyhurricane.target_info import parse_target_info


def normalized_target(target: str) -> str:
    """Normalize authority spelling without conflating URL scopes or evidence locations."""
    info = parse_target_info(target)
    host = info.host.lower()
    authority = f"[{host}]" if ":" in host else host
    if info.url:
        parsed = urlsplit(info.url)
        scheme = parsed.scheme.lower()
        port = parsed.port
        if port is not None and port != {"http": 80, "https": 443}.get(scheme):
            authority = f"{authority}:{port}"
        # Preserve credentials verbatim rather than merging distinct submitted locations.
        if "@" in parsed.netloc:
            authority = f"{parsed.netloc.rsplit('@', 1)[0]}@{authority}"
        result = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, parsed.fragment))
        # urlunsplit drops empty delimiters, which may still be meaningful to a target.
        if "?" in info.url.split("#", 1)[0] and not parsed.query:
            result = result.replace("#", "?#", 1) if "#" in result else f"{result}?"
        if "#" in info.url and not parsed.fragment:
            result = f"{result}#"
        return result
    return f"{authority}:{info.port}" if info.port is not None else authority


def finding_fingerprint(target: str, markdown: str) -> str:
    """Ignore presentation-only differences; titles are deliberately outside the identity."""
    body = markdown.replace("\r\n", "\n").replace("\r", "\n").strip()
    encoded = json.dumps([normalized_target(target), body], ensure_ascii=False).encode("utf-8")
    return f"v1:{hashlib.sha256(encoded).hexdigest()}"


@contextmanager
def finding_save_lock(path: Path):
    """Hold one assessment-wide lock through lookup, persistence, and downstream handoff."""
    with path.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)
