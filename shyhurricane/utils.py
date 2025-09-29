import base64
import datetime
import ipaddress
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Dict, Union, List, Tuple, AsyncGenerator
from urllib.parse import ParseResult, urlparse
from zoneinfo import ZoneInfo

import validators
from bs4 import SoupStrainer, BeautifulSoup
from haystack import Document
from mcp import Resource
from mcp.types import TextResourceContents
from pydantic import BaseModel, Field, ValidationError
from tldextract import tldextract

logger = logging.getLogger(__name__)


class HttpResource(BaseModel):
    """
    This is the response from an HTTP request. Several important attributes of the request are present, including the URL,
    the HTTP method, the response code (status_code).

    The "contents" field has the resource content if the tool provides the full content. The "resource" field has the
    content metadata and a URI that can be used to fetch the content.
    """
    score: Optional[float] = Field(description="Matching score, higher is better")
    url: str = Field(description="The URL for the HTTP resource")
    host: str = Field(description="The hostname of the HTTP server")
    port: int = Field(description="The port of the HTTP server")
    domain: str = Field(description="The domain name of the HTTP server, built from the hostname")
    status_code: int = Field(description="The HTTP status code for the response")
    method: str = Field(description="The HTTP method that was used to request the resource")
    resource: Optional[Resource] = Field(description="A link to the resource content")
    contents: Optional[TextResourceContents] = Field(description="The resource content")
    response_headers: Optional[Dict[str, str]] = Field(description="The HTTP response headers")


SCHEME_TO_PORT = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ftp": 21,
    "ftps": 990,
    "ssh": 22,
    "sftp": 22,
    "ldap": 389,
    "ldaps": 636,
    "smtp": 25,
    "smtps": 465,
    "imap": 143,
    "imaps": 993,
    "pop3": 110,
    "pop3s": 995,
}

def urlparse_ext(url: str) -> ParseResult:
    # urlparse does not do validation, so we need to add our own
    url = url.strip()

    try:
        if not validators.url(url,
                              skip_ipv4_addr=False,
                              skip_ipv6_addr=False,
                              simple_host=True,
                              strict_query=False,
                              consider_tld=False,
                              ):
            raise ValueError()
    except ValidationError as ve:
        raise ValueError(ve)

    url_parsed = urlparse(url, 'http')
    if not url_parsed.netloc:
        raise ValueError()
    if url_parsed.port:
        port = url_parsed.port
    else:
        port = SCHEME_TO_PORT.get(url_parsed.scheme, -1)
    if port < 0 or port > 65535:
        netloc = url_parsed.hostname
    elif "://[" in url:
        # IPv6 address
        netloc = f"[{url_parsed.hostname}]:{port}"
    else:
        netloc = f"{url_parsed.hostname}:{port}"
    return ParseResult(
        scheme=url_parsed.scheme,
        netloc=netloc,
        params=url_parsed.params,
        path=url_parsed.path,
        query=url_parsed.query,
        fragment=url_parsed.fragment
    )


def extract_domain(hostname: str) -> Optional[str]:
    if not hostname:
        return None
    try:
        if ipaddress.ip_address(hostname):
            return ""
    except ValueError:
        pass
    domain = tldextract.extract(hostname, include_psl_private_domains=True).top_domain_under_public_suffix
    if not domain:
        return '.'.join(hostname.split(".")[-2:])
    return domain


async def read_last_text_bytes(file, max_bytes=1024, encoding='utf-8') -> str:
    size = await file.tell()
    to_read = min(size, max_bytes)
    await file.seek(size - to_read, 0)
    chunk = await file.read(to_read)
    return chunk.decode(encoding, errors="ignore")


def parse_http_request(request_text):
    lines = request_text.splitlines()
    headers = {}
    body_lines = []
    response_lines = []
    in_headers = True
    method, path, http_version = None, None, None

    for i, line in enumerate(lines):
        if i == 0:
            # Request line
            try:
                method, path, http_version = line.strip().split()
            except ValueError:
                pass  # Malformed request line
            continue

        if len(response_lines) > 0:
            response_lines.append(line)
        elif in_headers:
            if line.strip() == "":
                in_headers = False
                continue
            key, sep, value = line.partition(":")
            if sep:
                key = key.strip().title()
                value = value.strip()
                if key in headers:
                    if isinstance(headers[key], list):
                        headers[key].append(value)
                    else:
                        headers[key] = ', '.join([headers[key], value])
                else:
                    headers[key] = value
        elif line.startswith("HTTP/"):
            # start of response
            response_lines.append(line)
        else:
            body_lines.append(line)

    body = "\n".join(body_lines)
    response = "\n".join(response_lines)
    return method, path, http_version, headers, body, response


def parse_http_response(response_text) -> Tuple[
    Optional[int],
    Dict[str, Union[str, list[str]]],
    str]:
    lines = response_text.splitlines()
    headers = {}
    body_lines = []
    in_headers = True
    status_code = None

    for i, line in enumerate(lines):
        if in_headers:
            if line.strip() == "":
                in_headers = False
                continue
            if line.startswith("HTTP/"):
                try:
                    status_code = int(line.split()[1])
                except (IndexError, ValueError):
                    status_code = None
            else:
                key, sep, value = line.partition(":")
                if sep:
                    key = key.strip().title()
                    value = value.strip()
                    # handle multiple headers like set-cookie
                    if key in headers:
                        if isinstance(headers[key], list):
                            headers[key].append(value)
                        else:
                            headers[key] = ', '.join([headers[key], value])
                    else:
                        headers[key] = value
        else:
            body_lines.append(line)

    body = "\n".join(body_lines)
    return status_code, headers, body


class PortScanResult(BaseModel):
    hostname: Optional[str] = Field(description="Hostname")
    ip_address: Optional[str] = Field(description="IP address")
    port: int = Field(description="Port number")
    state: str = Field(description="Port state: open, closed, or filtered")
    service_name: Optional[str] = Field(description="Service name")
    service_notes: Optional[str] = Field(description="Notes on the service")


class PortScanResults(BaseModel):
    results: List[PortScanResult] = Field(description="List of individual port scan results")
    targets: List[str] = Field(description="List of targets")
    ports: List[str] = Field(description="List of ports: individual ports or ranges")
    runtime_ts: float = Field(description="When the scan was run")
    nmap_xml: str = Field(description="NMAP XML output")
    has_more: bool = Field(False, description="Whether there are more results")


def is_katana_jsonl(value: str):
    logger.debug("is_katana_jsonl: %s ... %s", value[0:64], value[-64:])
    try:
        data = json.loads(value)
        if "request" not in data or "response" not in data or "timestamp" not in data:
            return False
        if "endpoint" in data["request"]:
            logger.debug("is_katana_jsonl: found")
            return True
        return False
    except Exception as e:
        logger.debug("is_katana_jsonl: parsing %d bytes: %s", len(value), e)
        return False


def is_har_json(value: str):
    logger.debug("is_har_json: %s", value[0:128])
    try:
        data = json.loads(value)
        if "log" not in data:
            return False
        return "entries" in data["log"]
    except Exception:
        return False


http_request_re = re.compile(
    r"^[A-Z][A-Z]+ [^\r\n]+ HTTP/[0-9][0-9.]*$",
    re.MULTILINE
)

http_response_re = re.compile(
    r"^HTTP/[0-9][0-9.]* \d{3} .+",
    re.MULTILINE
)


def is_http_raw(value: str):
    logger.debug("is_http_raw: %s", value[0:128])
    try:
        return bool(http_request_re.search(value) and http_response_re.search(value))
    except Exception:
        return False


class BeautifulSoupExtractor:
    def __init__(self):
        self._soup_strainer = SoupStrainer(['title', 'meta'])

    def extract(self, html: str) -> Tuple[Optional[str], Optional[str]]:
        soup = BeautifulSoup(html, 'html.parser', parse_only=self._soup_strainer)

        title = None
        description = None

        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        else:
            # Try fallback meta-tags in priority order
            title_fallbacks = [
                ('property', 'og:title'),
                ('name', 'twitter:title'),
                ('itemprop', 'name'),
            ]
            for attr, value in title_fallbacks:
                tag = soup.find('meta', attrs={attr: value})
                if tag and tag.get('content', ''):
                    title = tag['content'].strip()
                    break

            # extract description
        for meta in soup.find_all('meta'):
            attrs = meta.attrs
            meta_content = attrs.get('content', '')
            if not meta_content:
                continue

            if attrs.get('name') == 'description':
                description = meta_content.strip()
            elif attrs.get('property') == 'og:description':
                description = meta_content.strip()
            elif attrs.get('name') == 'twitter:description':
                description = meta_content.strip()
            elif attrs.get('itemprop') == 'description':
                description = meta_content.strip()

        return title, description


def remove_unencodable(text, encoding="utf-8"):
    if text is None:
        return None
    return text.encode(encoding, errors="ignore").decode(encoding)


def parse_to_iso8601(timestr: str) -> Tuple[str, float]:
    # Maps timezone abbreviations to IANA timezone names
    tz_abbrev_to_iana = {
        "CDT": "America/Chicago",
        "CST": "America/Chicago",
        "EDT": "America/New_York",
        "EST": "America/New_York",
        "MDT": "America/Denver",
        "MST": "America/Denver",
        "PDT": "America/Los_Angeles",
        "PST": "America/Los_Angeles",
        "GMT": "UTC",
        "UTC": "UTC",
    }

    # Try format 1: "Sat Jul 19 08:23:11 CDT 2025"
    m1 = re.match(r"^(\w{3}) (\w{3}) (\d{1,2}) (\d{2}:\d{2}:\d{2}) (\w{3}) (\d{4})$", timestr)
    if m1:
        _, month, day, time_str, tz_abbrev, year = m1.groups()
        tz = ZoneInfo(tz_abbrev_to_iana[tz_abbrev])
        dt = datetime.datetime.strptime(f"{month} {day} {year} {time_str}", "%b %d %Y %H:%M:%S")
        return dt.replace(tzinfo=tz).isoformat(), dt.timestamp()

    # Try format 2: "Sat, 19 Jul 2025 13:23:10 GMT"
    m2 = re.match(r"^\w{3}, (\d{1,2}) (\w{3}) (\d{4}) (\d{2}:\d{2}:\d{2}) (\w{3})$", timestr)
    if m2:
        day, month, year, time_str, tz_abbrev = m2.groups()
        tz = ZoneInfo(tz_abbrev_to_iana[tz_abbrev])
        dt = datetime.datetime.strptime(f"{day} {month} {year} {time_str}", "%d %b %Y %H:%M:%S")
        return dt.replace(tzinfo=tz).isoformat(), dt.timestamp()

    # Try format 3: ISO-8601, e.g. 2025-06-28T22:44:56.069000[Z|±HH:MM]
    try:
        # Python’s fromisoformat handles sub-second precision and offsets but not “Z”,
        # so normalise Z ➜ +00:00 for portability.
        iso_str = timestr.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:  # assume UTC when no offset provided
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.isoformat(), dt.timestamp()
    except ValueError:
        pass

    raise ValueError(f"Unrecognized time format: {timestr}")


def documents_sort_unique(documents: List[Document], limit: Optional[int] = None) -> List[Document]:
    documents.sort(key=lambda x: (x.score or 0, x.meta.get("timestamp_float", 0)), reverse=True)

    # unique per (URL, method, status code)
    unique_keys = set()
    unique_docs = []
    for doc in documents:
        key = (doc.meta["url"], doc.meta.get("http_method", "GET"), doc.meta.get("status_code", 200))
        if key not in unique_keys:
            unique_keys.add(key)
            unique_docs.append(doc)

    if limit is not None:
        unique_docs = unique_docs[:limit]

    return unique_docs


def filter_hosts_and_addresses(input: Optional[List[str]] = None) -> List[str]:
    if not input:
        return []
    result = []
    for e in input:
        try:
            if e == "localhost" or validators.domain(e) == True or ipaddress.ip_address(e):  # noqa: E712
                result.append(e)
        except (ValueError, ValidationError):
            pass
    return result


def filter_ip_networks(input: Optional[List[str]] = None) -> List[str]:
    if not input:
        return []
    result = []
    for e in input:
        try:
            if ipaddress.ip_address(e) or ipaddress.ip_network(e):
                result.append(e)
        except (ValueError, ValidationError):
            pass
    return result


async def stream_lines(byte_stream: AsyncGenerator[bytes, None]):
    buffer = b""
    async for chunk in byte_stream:
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            yield line.decode("utf-8", errors="replace").strip()
    if buffer:
        yield buffer.decode("utf-8", errors="replace").strip()


def query_to_netloc(query: str) -> Tuple[str | None, int | None]:
    port = None
    if query:
        query = query.lower()
        if "://" in query:
            try:
                parsed = urlparse_ext(query)
                query = parsed.hostname
                port = parsed.port
            except Exception:
                query = None
        elif ":" in query:
            try:
                query, _, port_str = query.rpartition(":")
                if query.startswith("[") and query.endswith("]"):
                    query = query[1:-1]
                try:
                    if validators.domain(query) == False and not ipaddress.ip_address(query):  # noqa: E712
                        query = None
                    else:
                        port = int(port_str)
                        if port < 0 or port > 65535:
                            port = None
                except (ValueError, ValidationError):
                    query = None

            except Exception:
                query = None
    return query, port


def munge_urls(query) -> Tuple[Optional[str], Optional[List[str]]]:
    """
    Munges URLs for query purposes. Returns variants with and without a trailing slash, with and without query string.
    :return: url prefix for starts with operators, list of URLs for 'in' operators
    """
    if not query.strip():
        return "", []
    if "://" not in query:
        return query, [query]
    query_url = query
    urls_munged = [query]
    url_prefix = None
    if '?' in query_url:
        query_url = query_url.split('?')[0]
        urls_munged.append(query_url)
        url_prefix = query_url + "?"
    if query_url.endswith('/'):
        urls_munged.append(query_url[:-1])
        if not url_prefix:
            url_prefix = query_url
    else:
        urls_munged.append(query_url + '/')
        if not url_prefix:
            url_prefix = query_url + '/'
    return url_prefix, urls_munged


def unix_command_image() -> str:
    return "ghcr.io/double16/shyhurricane_unix_command:main"


def get_state_path(db: str, state_name: str) -> Path:
    if os.path.exists("/data"):
        # Running inside a container
        path = Path("/data", state_name)
    else:
        path = Path(Path.home(), ".local", "state", "shyhurricane", re.sub(r'[^A-Za-z0-9_.-]', '_', db), state_name)
    os.makedirs(path, mode=0o755, exist_ok=True)
    return path


def get_log_path(db: str, log_name: str) -> Path:
    path = Path(get_state_path(db, "logs"), log_name)
    return path


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


_word_re = re.compile(r"\w+")

def collapse_first_repeated_sequence(s: str) -> str:
    # Tokenize words and keep spans into original string
    words: List[str] = []
    spans: List[Tuple[int, int]] = []
    for m in _word_re.finditer(s):
        words.append(m.group(0))
        spans.append((m.start(), m.end()))
    n = len(words)
    if n < 2:
        return s

    # Find first immediately repeated block starting at i of size k
    for i in range(n - 1):
        max_k = (n - i) // 2
        for k in range(1, max_k + 1):
            block = words[i:i+k]
            # Must repeat immediately
            if words[i+k:i+2*k] != block:
                continue
            # And from i to the end, it must be *only* repetitions of block
            tail = words[i:]
            if len(tail) % k != 0:
                continue
            reps = len(tail) // k
            if all(tail[j*k:(j+1)*k] == block for j in range(reps)):
                # OK to collapse: keep prefix + one copy of the block (+ its trailing punctuation)
                end = spans[i + k - 1][1]
                j = end
                # include trailing punctuation directly after the block (stop at whitespace or word char/_)
                while j < len(s) and not s[j].isspace() and not s[j].isalnum() and s[j] != '_':
                    j += 1
                return s[:j]
            # Otherwise, unrepeated words exist at the end → do not dedupe
            return s
    return s
