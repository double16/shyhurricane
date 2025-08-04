import asyncio
import unittest

from shyhurricane.mcp_server.tools.web_search import web_search


class WebSearchTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_ddg_python3(self):
        result = asyncio.run(web_search(None, "python3 features"))
        self.assertIsNotNone(result)
        self.assertTrue(len(result.hits) > 0, "no results")
        self.assertTrue("python" in result.hits[0].snippet.lower(), "python3 not in results: " + result.hits[0].snippet)
