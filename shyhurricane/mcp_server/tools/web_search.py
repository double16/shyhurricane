import asyncio
import random

from duckduckgo_search.exceptions import RatelimitException, TimeoutException
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from duckduckgo_search import DDGS
from typing import List, Callable

from shyhurricane.mcp_server import mcp_instance, log_tool_history


class WebSearchHit(BaseModel):
    title: str = Field(description="Result title")
    url: str = Field(description="Result url")
    snippet: str = Field(description="Result snippet")


def search_duckduckgo(query: str, num: int) -> List[WebSearchHit]:
    with DDGS() as ddg:
        results = ddg.text(query, backend="html", max_results=num)
        return [WebSearchHit(title=r["title"], url=r["href"], snippet=r["body"])
                for r in results]


def with_backoff(fn: Callable[..., List[WebSearchHit]],
                 retries: int = 4,
                 base: float = 1.5,
                 jitter: float = 0.3):
    """Decorate *fn* so it retries with exponential back-off on 429/5xx."""

    async def wrapper(*args, **kwargs):
        delay = base
        last_exc = None
        for attempt in range(retries + 1):
            try:
                hits = await asyncio.to_thread(fn, *args, **kwargs)
                if len(hits) == 0:
                    raise TimeoutException("no results")
                return hits
            except Exception as exc:
                last_exc = exc
                if attempt >= retries:
                    raise exc
                # Only retry obvious transient problems
                if isinstance(exc, RatelimitException):
                    pass
                elif isinstance(exc, TimeoutException):
                    pass
                else:
                    msg = str(exc).lower()
                    if "429" not in msg and "rate" not in msg and "timeout" not in msg \
                            and "temporarily unavailable" not in msg:
                        raise exc
                sleep_for = delay * (1 + random.uniform(-jitter, jitter))
                await asyncio.sleep(max(0.1, sleep_for))
                delay *= base
        raise last_exc

    return wrapper


class WebSearchResult(BaseModel):
    instructions: str = Field(description="The instructions for interpreting the search results")
    query: str = Field(description="The query string used by the search")
    hits: List[WebSearchHit] = Field(description="Hits from the search results")


websearch_instructions = "These are the results from searching the web for the provided query."


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Search the web for general information",
        readOnlyHint=True,
        openWorldHint=True),
)
async def web_search(ctx: Context, query: str, limit: int = 20) -> WebSearchResult:
    """
    Searches the web with the provided query. The query is a keyword search that may include common search operators
    such as:

    | Example | Result |
    | ------- | ------ |
    | cats dogs | Results about cats or dogs |
    | "cats and dogs" | Results for exact term "cats and dogs". If no or few results are found, we'll try to show related results. |
    | ~"cats and dogs" | Experimental syntax: more results that are semantically similar to "cats and dogs", like "cats & dogs" and "dogs and cats" in addition to "cats and dogs". |
    | cats -dogs | Fewer dogs in results |
    | cats +dogs | More dogs in results |
    | cats filetype:pdf | PDFs about cats. Supported file types: pdf, doc(x), xls(x), ppt(x), html |
    | dogs site:example.com | Pages about dogs from example.com |
    | cats -site:example.com | Pages about cats, excluding example.com |
    | intitle:dogs | Page title includes the word "dogs" |
    | inurl:cats | Page URL includes the word "cats" |

    Invoke this tool when the user needs to find general information on vulnerabilities, CVEs, published exploits,
    and instructions for using tools. When searching for published exploits, in additional to this tool,
    also try running the `searchsploit` command.

    Never include sensitive information such as personally identifiable information (PII), payment card data, health care
    information, etc.
    """
    await log_tool_history(ctx, "web_search", query=query, limit=limit)
    limit = max(1, min(50, limit))

    search_fn = with_backoff(search_duckduckgo)
    hits = await search_fn(query, limit)

    await log_tool_history(ctx, "web_search: result", query=query, limit=limit, hits=len(hits))

    return WebSearchResult(
        instructions=websearch_instructions,
        query=query,
        hits=hits,
    )
