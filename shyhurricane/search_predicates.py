"""Deterministic query predicates for indexed HTTP resources."""

import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

OPERATORS = {"site", "inurl", "filetype", "ext", "mime", "method", "status", "type"}
HTTP_TYPES = {"html", "javascript", "css", "xml", "json", "network", "forms", "content", "default"}
TOKEN = re.compile(r"""(?:[^\s"']|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+""")


@dataclass(frozen=True)
class Predicate:
    operator: str
    value: str
    exclude: bool = False

    def matches_netloc(self, netloc: str) -> bool:
        """Match site host/port scope against stored network locations, including bare IPv6."""
        target = urlsplit(self.value if "://" in self.value else f"//{self.value}")
        host, _, port = netloc.rpartition(":")
        if ":" in host and not host.startswith("["):
            netloc = f"[{host}]:{port}"
        return Predicate("site", target.netloc).matches({"url": f"http://{netloc}/"})

    def matches(self, meta: dict, response_mime: str | None = None) -> bool:
        url = urlsplit(meta.get("url", ""))
        if self.operator == "site":
            target = urlsplit(self.value if "://" in self.value else f"//{self.value}")
            host, wanted = (url.hostname or "").lower(), target.hostname.lower()
            try:
                ipaddress.ip_address(wanted)
                host_match = host == wanted
            except ValueError:
                host_match = host == wanted or host.endswith(f".{wanted}")
            port = url.port or {"https": 443, "http": 80}.get(url.scheme)
            match = (
                host_match
                and (target.port is None or target.port == port)
                and (not target.scheme or target.scheme == url.scheme)
                and (not target.path or url.path.startswith(target.path))
            )
        elif self.operator == "inurl":
            match = self.value in meta.get("url", "")
        elif self.operator == "filetype":
            filename = url.path.rsplit("/", 1)[-1]
            match = "." in filename and filename.rsplit(".", 1)[-1].lower() == self.value
        elif self.operator == "mime":
            match = response_mime is not None and response_mime.lower().split(";", 1)[0].strip() == self.value
        elif self.operator == "method":
            match = meta.get("http_method", "").upper() == self.value
        elif self.operator == "status":
            match = meta.get("status_code") == int(self.value)
        else:
            match = meta.get("type") == self.value
        return not match if self.exclude else match


def parse_predicates(query: str) -> tuple[str, list[Predicate]]:
    """Remove supported predicates while preserving all other query text."""
    predicates = []
    remaining = []
    end = 0
    for token in TOKEN.finditer(query):
        text = token.group()
        operator, separator, value = text.lstrip("-").partition(":")
        if separator and operator.lower() in OPERATORS and not text.startswith("--"):
            operator = operator.lower()
            if value.startswith(("\"", "'")):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ValueError(f"Unterminated quoted value for {operator}:")
                value = re.sub(r"\\([\\\"'])", r"\1", value[1:-1])
            if not value:
                raise ValueError(f"{operator}: requires a value")
            if operator == "ext":
                operator = "filetype"
            if operator in {"filetype", "mime", "type"}:
                value = value.lower()
            if operator == "site":
                target = urlsplit(value if "://" in value else f"//{value}")
                if (
                    not target.hostname or target.username or target.password
                    or target.query or target.fragment or target.scheme not in {"", "http", "https"}
                    or not re.fullmatch(r"[a-zA-Z0-9_.:-]+", target.hostname)
                ):
                    raise ValueError("site: requires a hostname, IP address, or HTTP(S) URL")
                if target.port is not None and not 1 <= target.port <= 65535:
                    raise ValueError("site: port must be between 1 and 65535")
            elif operator == "filetype":
                value = value.lstrip(".")
                if not re.fullmatch(r"[a-z0-9_-]+", value):
                    raise ValueError("filetype: requires a file extension, such as js")
            elif operator == "mime" and not re.fullmatch(r"[\w!#$&^.+-]+/[\w!#$&^.+-]+", value):
                raise ValueError("mime: requires a MIME type, such as application/json")
            elif operator == "method":
                value = value.upper()
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", value):
                    raise ValueError("method: requires an HTTP method")
            elif operator == "status" and (not value.isascii() or not value.isdigit() or not 100 <= int(value) <= 599):
                raise ValueError("status: requires a response code between 100 and 599")
            elif operator == "type" and value not in HTTP_TYPES:
                raise ValueError(f"type: must be one of {', '.join(sorted(HTTP_TYPES))}")
            predicates.append(Predicate(operator, value, text.startswith("-")))
            remaining.append(query[end:token.start()])
            end = token.end()
    remaining.append(query[end:])
    return "".join(remaining).strip(), predicates


def resource_key(meta: dict) -> tuple:
    """Identify the same captured response across indexed representations."""
    return tuple(meta.get(key) for key in ("url", "http_method", "status_code", "timestamp"))


def response_mime(meta: dict) -> str | None:
    if meta.get("type") not in {"network", "forms"}:
        return meta.get("content_type")
    try:
        headers = json.loads(meta.get("response_headers", "{}"))
    except (ValueError, TypeError):
        return None
    if isinstance(headers, dict):
        return next((value for key, value in headers.items() if key.lower() == "content-type"), None)
    return None
