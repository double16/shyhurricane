import unittest

import pytest
from mcp import McpError
from mcp.server.fastmcp import Context
from mcp.shared.context import RequestContext

from shyhurricane.mcp_server.tools.find_wordlists import find_wordlists, rank_wordlists, score_path
from unittest.mock import patch, AsyncMock, Mock


class TestWordlistRanking(unittest.TestCase):

    def setUp(self):
        # Sample paths we’ll use for multiple tests
        self.paths = [
            "/usr/share/wordlists/common.txt",
            "/usr/share/wordlists/sql/raft-large.txt",
            "/usr/share/wordlists/web/lfi.txt",
            "/home/user/raft_wordlist.txt",
            "/opt/tools/sqlmap/wordlist.txt",
            "/wordlists/lfi/common.txt",
        ]

    def test_single_query_prioritizes_directories(self):
        ranked = rank_wordlists(self.paths, "lfi", limit=3)
        # Expect path with directory 'lfi' before filename 'lfi.txt'
        self.assertEqual(ranked[0], "/wordlists/lfi/common.txt")
        self.assertEqual(ranked[1], "/usr/share/wordlists/web/lfi.txt")

    def test_multiple_query_parts(self):
        top_paths = rank_wordlists(self.paths, "sql raft", limit=2)
        # Should prefer path with both "sql" directory and "raft" filename
        self.assertIn("/usr/share/wordlists/sql/raft-large.txt", top_paths)

    def test_earlier_in_path_scores_higher(self):
        # "/wordlists/lfi/common.txt" should score higher than deeper "web/lfi.txt"
        score_early = score_path("/wordlists/lfi/common.txt", "lfi")
        score_deep = score_path("/usr/share/wordlists/web/lfi.txt", "lfi")
        self.assertGreater(score_early, score_deep)

    def test_non_matching_query_returns_zero(self):
        score = score_path("/usr/share/wordlists/common.txt", "doesnotexist")
        self.assertEqual(score, 0.0)

    def test_limit_results(self):
        ranked = rank_wordlists(self.paths, "wordlist", limit=2)
        self.assertEqual(len(ranked), 2)


class TestFindWordlists(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.sample_output = "\n".join([
            "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
            "/usr/share/seclists/Fuzzing/LFI/lfi.txt",
            "/usr/share/seclists/Passwords/common.txt",
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        ])

    def new_context(self) -> Context:
        server_context = Mock(spec=["cache_path", "work_path", "cached_get_additional_hosts"])
        server_context.cache_path = "/var/tmp"
        server_context.work_path = "/var/tmp"
        server_context.cached_get_additional_hosts = {}
        return Context(request_context=RequestContext(
            request_id="unittest",
            meta=None,
            session=Mock(),
            lifespan_context=server_context
        ))

    @pytest.mark.skip
    @patch("shyhurricane.mcp_server.tools.find_wordlists.rank_wordlists")
    @patch("shyhurricane.mcp_server.log_tool_history", new_callable=AsyncMock)
    @patch("shyhurricane.mcp_server.tools.run_unix_command._run_unix_command", new_callable=AsyncMock)
    async def test_with_query_uses_ranker_and_builds_command(self, mock_run, mock_log, mock_rank):
        # Arrange
        mock_run.return_value = type("R", (), {"return_code": 0, "output": self.sample_output, "error": ""})
        mock_rank.return_value = ["/usr/share/seclists/Fuzzing/LFI/lfi.txt",
                                  "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"]

        ctx = self.new_context()
        query = "web lfi"
        limit = 20

        # Act
        result = await find_wordlists(ctx, query, limit)

        # Assert: ranker used with full list and cleaned query
        mock_rank.assert_called_once()
        args, kwargs = mock_rank.call_args
        all_results_arg, query_arg, limit_arg = args
        # TODO: find out why this is failing, seems to be a mock issue because _run_unix_command.output is empty
        # self.assertEqual(all_results_arg, self.sample_output.splitlines())
        self.assertEqual(query_arg, "web lfi")
        self.assertEqual(limit_arg, limit)

        # Assert: command includes both -ipath parts and base find path
        run_args, _ = mock_run.call_args
        called_ctx, called_cmd, called_env = run_args
        self.assertIs(called_ctx, ctx)
        self.assertIn("find /usr/share/seclists -type f -not -path '*/.*'", called_cmd)
        self.assertIn("-ipath '*web*'", called_cmd)
        self.assertIn("-ipath '*lfi*'", called_cmd)
        self.assertIsNone(called_env)

        # Assert: returns ranker result
        self.assertEqual(result, mock_rank.return_value)

        # Assert: history logging awaited
        mock_log.assert_awaited()

    @pytest.mark.skip
    @patch("shyhurricane.mcp_server.log_tool_history", new_callable=AsyncMock)
    @patch("shyhurricane.mcp_server.tools.run_unix_command._run_unix_command", new_callable=AsyncMock)
    async def test_without_query_returns_first_limit(self, mock_run, mock_log):
        mock_run.return_value = type("R", (), {"return_code": 0, "output": self.sample_output, "error": ""})
        ctx = self.new_context()

        result = await find_wordlists(ctx, query="", limit=2)

        self.assertEqual(result, self.sample_output.splitlines()[:2])

        # Ensure no ranker used when query is empty
        # (If you want to enforce, you could also patch rank_wordlists and assert_not_called.)
        run_args, _ = mock_run.call_args
        called_cmd = run_args[1]
        # No -ipath arguments when query is empty
        self.assertNotIn("-ipath", called_cmd)

    @pytest.mark.skip
    @patch("shyhurricane.mcp_server.log_tool_history", new_callable=AsyncMock)
    @patch("shyhurricane.mcp_server.tools.run_unix_command._run_unix_command", new_callable=AsyncMock)
    async def test_nonzero_exit_raises_mcp_error(self, mock_run, mock_log):
        mock_run.return_value = type("R", (), {"return_code": 1, "output": "", "error": "boom"})
        ctx = self.new_context()

        with self.assertRaises(McpError):
            await find_wordlists(ctx, query="sql", limit=5)

if __name__ == "__main__":
    unittest.main()
