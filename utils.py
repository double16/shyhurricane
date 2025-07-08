from pathlib import Path
from urllib.parse import ParseResult, urlparse
from typing import Optional

from mcp import Resource
from pydantic import BaseModel, Field


class HttpResource(BaseModel):
    score: Optional[float] = Field(description="Matching score, higher is better")
    url: str = Field(description="The URL for the HTTP resource")
    host: str = Field(description="The host name of the HTTP server")
    port: int = Field(description="The port of the HTTP server")
    domain: str = Field(description="The domain name of the HTTP server, built from the host name")
    status_code: int = Field(description="The HTTP status code for the response")
    method: str = Field(description="The HTTP method that was used to request the resource")
    resource: Optional[Resource] = Field(description="A link to the resource content")


def urlparse_ext(url: str) -> ParseResult:
    url_parsed = urlparse(url, 'http')
    if url_parsed.port:
        port = url_parsed.port
    elif url_parsed.scheme == "http":
        port = 80
    elif url_parsed.scheme == "https":
        port = 443
    else:
        port = -1
    return ParseResult(
        scheme=url_parsed.scheme,
        netloc=f"{url_parsed.hostname}:{port}",
        params=url_parsed.params,
        path=url_parsed.path,
        query=url_parsed.query,
        fragment=url_parsed.fragment
    )


def latest_mtime(db: Path) -> float:
    """
    Get the latest modified time of the database.
    :param db: path to the database.
    :return:  the latest modified time as a float.
    """
    return max(f.stat().st_mtime for f in db.rglob("*.sqlite3") if f.is_file())
