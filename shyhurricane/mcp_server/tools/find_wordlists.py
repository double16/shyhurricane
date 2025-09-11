import re
from typing import List, Annotated

from mcp import McpError
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, ErrorData, INTERNAL_ERROR
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import RunUnixCommand, _run_unix_command


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Wordlists",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_wordlists(
        ctx: Context,
        query: Annotated[str, Field(description="""Substring search of the path. Examples: Web-Content, DNS, LFI, password, username""")],
        limit: Annotated[int, Field(20, description="The maximum number of results to return", ge=1, le=1000)] = 20
) -> List[str]:
    """
    Find available word lists. The results can be used with other commands that have options to
    accept word lists.

    Invoke this tool when the user wants to run a brute-forcing tool and needs to use a wordlist.
    """
    await log_tool_history(ctx, "find_wordlists", query=query)
    command = "find /usr/share/seclists -type f -not -path '*/.*'"
    if query and query.strip():
        query_clean = re.sub(r'[^\w\s\-_.]', '', query)
        command = f"find /usr/share/seclists -type f -not -path '*/.*'"
        for query_part in query_clean.split(maxsplit=10):
            command += f" -ipath '*{query_part}*'"
    result: RunUnixCommand = await _run_unix_command(ctx, command, None)
    if result.return_code != 0:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to find word lists: {result.error}"))
    return result.output.splitlines()[:limit]
