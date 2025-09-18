import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Iterable, List

from mcp import McpError
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, ErrorData, INTERNAL_ERROR
from pydantic import Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.tools.run_unix_command import RunUnixCommand, _run_unix_command


def _split_components(path: str) -> List[str]:
    # Works across platforms without touching the filesystem
    if "\\" in path and (":" in path or path.count("\\") >= path.count("/")):
        p = PureWindowsPath(path)
    else:
        p = PurePosixPath(path)
    return [str(c) for c in p.parts] or [path]


def score_path(path: str, query: str) -> float:
    """
    Higher score = better. Factors:
      - directory component matches weigh more than filename matches
      - earlier path components weigh more than later ones
      - exact component == query part gets a small bonus
    """
    parts = [q for q in query.lower().split() if q]
    if not parts:
        return 0.0

    comps = _split_components(path)
    n = len(comps)
    if n == 0:
        return 0.0

    # Pre-lower once
    comps_l = [c.lower() for c in comps]

    total = 0.0
    for q in parts:
        best_for_q = 0.0
        for i, comp in enumerate(comps_l):
            if q in comp:
                is_filename = (i == n - 1)
                # Directory > filename
                dir_weight = 1.0 if not is_filename else 0.6

                # Earlier (smaller i) is better. 1/(1+i) drops off fast but smoothly.
                pos_weight = 1.0 / (1.0 + i)

                # Exact component match bonus (e.g., a directory literally named "lfi")
                exact_bonus = 0.5 if comp == q else 0.0

                # Slight bonus if the match starts earlier within the component
                # (kept tiny to avoid overfitting)
                start_idx = comps_l[i].find(q)
                intra_bonus = 0.1 * (1.0 / (1.0 + start_idx))

                score = dir_weight * pos_weight + exact_bonus + intra_bonus
                if score > best_for_q:
                    best_for_q = score

        total += best_for_q  # no penalty if a part isn’t present; tool already filtered

    # Normalize by number of query parts so more parts don't automatically inflate scores
    return total / len(parts)


def rank_wordlists(paths: Iterable[str], query: str, limit: int = 20) -> List[str]:
    scored = [(p, score_path(p, query)) for p in paths]
    # Sort by score desc, then shorter path (tiebreaker), then lexicographically
    scored.sort(key=lambda x: (-x[1], len(x[0]), x[0]))
    return list(map(lambda e: e[0], scored[:limit]))


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
    query_clean = re.sub(r'[^\w\s\-_.]', '', query.strip()) if query else ""
    if query_clean:
        command = "find /usr/share/seclists -type f -not -path '*/.*'"
        for query_part in query_clean.split(maxsplit=10):
            command += f" -ipath '*{query_part}*'"
    result: RunUnixCommand = await _run_unix_command(ctx, command, None)
    if result.return_code != 0:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to find word lists: {result.error}"))
    all_results = result.output.splitlines()
    if query_clean:
        return rank_wordlists(all_results, query_clean, limit)
    else:
        return all_results[:limit]
