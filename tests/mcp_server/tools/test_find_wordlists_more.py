import pytest
from mcp.server.mcpserver.exceptions import ToolError

import shyhurricane.mcp_server.tools.find_wordlists as wordlists


async def noop(*args, **kwargs):
    return None


class Result:
    def __init__(self, return_code=0, output="", error=""):
        self.return_code = return_code
        self.output = output
        self.error = error


def test_split_components_handles_windows_and_empty_query():
    assert wordlists._split_components(r"C:\tools\SecLists\LFI\common.txt")[-2:] == ["LFI", "common.txt"]
    assert wordlists.score_path("/wordlists/common.txt", "") == 0.0
    assert wordlists.rank_wordlists(["/b/long-name.txt", "/a/x.txt"], "", limit=2) == ["/a/x.txt", "/b/long-name.txt"]


@pytest.mark.asyncio
async def test_find_wordlists_builds_query_command_and_ranks(monkeypatch):
    calls = []

    async def run(ctx, command, env):
        calls.append((command, env))
        return Result(output="\n".join([
            "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
            "/usr/share/seclists/Fuzzing/LFI/lfi.txt",
            "/usr/share/seclists/Passwords/common.txt",
        ]))

    monkeypatch.setattr(wordlists, "log_tool_history", noop)
    monkeypatch.setattr(wordlists, "_run_unix_command", run)

    result = await wordlists.find_wordlists(object(), "web; lfi!", limit=2)

    assert "-ipath '*web*'" in calls[0][0]
    assert "-ipath '*lfi*'" in calls[0][0]
    assert calls[0][1] is None
    assert result.paths == [
        "/usr/share/seclists/Fuzzing/LFI/lfi.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
    ]


@pytest.mark.asyncio
async def test_find_wordlists_without_query_and_error(monkeypatch):
    async def run_ok(ctx, command, env):
        return Result(output="one\ntwo\nthree")

    async def run_bad(ctx, command, env):
        return Result(return_code=2, error="failed")

    monkeypatch.setattr(wordlists, "log_tool_history", noop)
    monkeypatch.setattr(wordlists, "_run_unix_command", run_ok)

    assert (await wordlists.find_wordlists(object(), "", limit=2)).paths == ["one", "three"]

    monkeypatch.setattr(wordlists, "_run_unix_command", run_bad)
    with pytest.raises(ToolError, match="Failed to find word lists"):
        await wordlists.find_wordlists(object(), "sql", limit=5)


@pytest.mark.asyncio
async def test_internal_wordlist_loader_keeps_all_candidates_without_snapshots(monkeypatch, result_store):
    async def run(ctx, command, env):
        return Result(output="\n".join(f"/path/{i}" for i in range(1005)))

    monkeypatch.setattr(wordlists, "log_tool_history", noop)
    monkeypatch.setattr(wordlists, "_run_unix_command", run)
    result = await wordlists.find_wordlists_all(None, "")
    assert len(result.paths) == 1005
    assert result.pagination is None
    assert not list(result_store.snapshots.iterdir())
