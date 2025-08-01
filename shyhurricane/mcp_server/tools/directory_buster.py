import asyncio
import logging
import os.path
import queue
import time
from multiprocessing import Queue
from typing import List, Optional, Dict

from mcp import McpError
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context, get_additional_hosts
from shyhurricane.mcp_server.tools.find_wordlists import find_wordlists
from shyhurricane.task_queue import DirBustingQueueItem

logger = logging.getLogger(__name__)

dirbuster_results_instructions_found = """These resources were found by brute-forcing the web server URL using a wordlist."""
dirbuster_results_instructions_has_more = " This list isn't all of the results. Use the find_web_resources and find_urls tools to get more."
dirbuster_results_instructions_not_found = "No resources were found by directory busting (brute-forcing) the site. It may be there is no web server at the requested address and port or a different wordlist is needed."


def dirbuster_instructions(results: List[str], has_more: bool) -> str:
    if results:
        instructions = dirbuster_results_instructions_found
        if has_more:
            instructions += dirbuster_results_instructions_has_more
    else:
        instructions = dirbuster_results_instructions_not_found
    return instructions


class DirBusterResults(BaseModel):
    instructions: str = Field(description="The instructions string for interpreting the results")
    starting_url: str = Field(description="The starting URL of the directory buster")
    wordlist: Optional[str] = Field(description="The wordlist used by the directory buster")
    urls: List[str] = Field(description="The urls found by the directory buster")
    has_more: bool = Field(
        description="Whether the directory buster has more resources available that can be retrieved using the find_web_resources tool or listed by the find_urls tool")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Directory Buster",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def directory_buster(
        ctx: Context,
        url: str,
        depth: int = 3,
        method: str = "GET",
        wordlist: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        extensions: Optional[List[str]] = None,
        ignored_response_codes: Optional[List[int]] = None,
        additional_hosts: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
) -> DirBusterResults:
    """
    Search a website for hidden directories and files. This tool uses a wordlist to append each word to a URL and see if
    it responds.

    Invoke this tool when the user wants to run a directory busting (i.e. brute-forcing) tool. The results are indexed and available in the
    find_web_resources, find_urls and other tools that use indexed content. This tool is preferred over feroxbuster,
    gobuster, ffuf, wfuzz, and other like commands.

    The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
    know the IP address for a host, be sure to include these in the additional_hosts parameter for
    commands to run properly in a containerized environment.

    The url may contain the FUZZ keyword that will be replaced with values from the wordlist. For example, "http://target.local/path/FUZZ".

    The user_agent can be used to specify the "User-Agent" request header. This is useful if a particular browser needs
    to be spoofed or the user requests extra information in the user agent header to identify themselves as a bug bounty hunter.
    The user_agent may contain the FUZZ keyword that will be replaced with values from the wordlist.

    The request_headers map is extra request headers sent with the request.The request_headers key and/or values may
    contain the FUZZ keyword that will be replaced with values from the wordlist.

    The extensions parameter specifies file extensions to search for such as pdf, php, etc. Do not include a leading
    period.

    The cookies parameter is name, value pairs for cookies to send with each request.

    The params is used to send either GET or POST parameters.

    The timeout_seconds parameter specifies how long to wait for responses before returning. Directory busting will
    continue after returning.

    Returns a list of URLs found. Indexes each URL that can be queried using the find_web_resources and find_urls tools. URL content can be returned using the fetch_web_resource_content tool.
    """
    await log_tool_history(ctx, "directory_buster", url=url, depth=depth, method=method, wordlist=wordlist,
                           extensions=extensions,
                           ignored_response_codes=ignored_response_codes, additional_hosts=additional_hosts,
                           user_agent=user_agent, request_headers=request_headers, cookies=cookies, params=params,
                           timeout_seconds=timeout_seconds)
    server_ctx = await get_server_context()
    assert server_ctx.open_world

    url = url.strip()
    depth = min(5, max(1, depth))

    # validate wordlist
    if wordlist:
        wordlist_filename = os.path.split(wordlist)[-1]
        try:
            wordlist_results = await find_wordlists(ctx, wordlist_filename)
            if len(wordlist_results) == 0:
                logger.warning("No wordlists found for %s, using default", wordlist_filename)
                wordlist = None
            elif wordlist in wordlist_results:
                logger.info("Validated wordlist %s", wordlist)
            else:
                original_wordlist = wordlist
                for found_wordlist in wordlist_results:
                    wordlist = found_wordlist
                    if found_wordlist.endswith("/" + wordlist_filename):
                        # exact filename, different path
                        break
                logger.info("Corrected wordlist from %s to %s", original_wordlist, wordlist)
        except McpError as e:
            logger.warning("Could not validate wordlist, using as given: %s", e)

    task_queue: Queue = server_ctx.task_queue
    dir_busting_result_queue: Queue = server_ctx.dir_busting_result_queue
    queue_item = DirBustingQueueItem(
        uri=url,
        depth=depth,
        method=method,
        wordlist=wordlist,
        extensions=extensions,
        ignored_response_codes=ignored_response_codes,
        user_agent=user_agent,
        request_headers=request_headers,
        cookies=cookies,
        params=params,
        additional_hosts=get_additional_hosts(ctx, additional_hosts),
        seclists_volume=server_ctx.seclists_volume,
    )
    await asyncio.to_thread(task_queue.put, queue_item)
    results: List[str] = []
    has_more = True
    time_limit = time.time() + min(600, max(30, timeout_seconds or 120))
    while time.time() < time_limit:
        try:
            found_url: str = await asyncio.to_thread(
                dir_busting_result_queue.get,
                timeout=(max(1.0, time_limit - time.time())))
        except (queue.Empty, TimeoutError):
            break
        if found_url is None:
            has_more = False
            break
        logger.debug(f"{found_url} has been retrieved")
        if not found_url.startswith(url):
            logger.debug(
                f"Dir buster queued {found_url}, expecting {url}*")
            continue
        results.append(found_url)
        await ctx.info(f"Found: {found_url}")

    instructions = dirbuster_instructions(results, has_more)
    return DirBusterResults(
        instructions=instructions,
        starting_url=url,
        wordlist=wordlist,
        urls=results,
        has_more=has_more,
    )
