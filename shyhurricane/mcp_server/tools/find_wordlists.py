import re
from typing import List

from mcp import McpError
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, ErrorData, INTERNAL_ERROR

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import RunUnixCommand, _run_unix_command


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="List Wordlists",
        readOnlyHint=True,
        openWorldHint=False),
)
async def find_wordlists(ctx: Context, query: str) -> List[str]:
    """
    Find available word lists. The results can be used with other commands that have options to
    accept word lists.

    Invoke this tool when the user wants to run a brute-forcing tool and needs to use a wordlist.

    The query is a substring search of the path. Examples: Web, DNS, LFI, etc.
    """
    await log_tool_history(ctx, "find_wordlists")
    command = "find /usr/share/seclists -type f -not -path '*/.*'"
    if query and query.strip():
        query_clean = re.sub(r'[^\w\-_.]', '', query)
        command = f"find /usr/share/seclists -type f -ipath '*{query_clean}*' -not -path '*/.*'"
    result: RunUnixCommand = await _run_unix_command(ctx, command, None)
    if result.return_code != 0:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to find word lists: {result.error}"))
    return result.output.splitlines()
