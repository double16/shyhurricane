import json
import unittest
from typing import List, Tuple

import pytest

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import build_website_context_pipeline


@pytest.mark.ollama
class WebsiteContextPipelineTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.pipeline = build_website_context_pipeline(generator_config=self.generator_config)

    def _run_pipeline(self, target_query: str) -> Tuple[List[str], List[str], List[str], List[str]]:
        doc_types: list[str] = []
        targets: list[str] = []
        methods: list[str] = []
        response_codes: list[str] = []
        target_result = \
            self.pipeline.run({'builder': {'query': target_query}}).get('llm', {}).get('replies', [""])[0]
        if target_result:
            try:
                target_json = json.loads(target_result)
                targets.extend(target_json.get('target', []))
                doc_types.extend(target_json.get('content', []))
                methods.extend(target_json.get('methods', []))
                response_codes.extend(target_json.get('response_codes', []))
            except json.decoder.JSONDecodeError:
                pass
        return doc_types, targets, methods, response_codes

    def _assert_empty_list(self, data: List[str]) -> None:
        self.assertEqual(0, len(list(filter(bool, data))), json.dumps(data))

    def test_single_website(self):
        doc_types, targets, methods, response_codes = self._run_pipeline("Examine http://vulernablesite.net for vulns")
        # self._assert_empty_list(doc_types)
        self.assertEqual(["http://vulernablesite.net"], targets)
        self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_single_hostname(self):
        doc_types, targets, methods, response_codes = self._run_pipeline("Examine vulernablesite.net for vulns")
        # self._assert_empty_list(doc_types)
        self.assertIn("vulernablesite.net", targets)
        self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_single_hostname2(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            "What origins are allowed via the Access-Control-Allow-Origin header on example.com?")
        # self._assert_empty_list(doc_types)
        # target could legit have http:// or https:// because we've referenced an HTTP header in the query
        self.assertIn("example.com", ' '.join(targets))
        self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_single_hostname3(self):
        doc_types, targets, methods, response_codes = self._run_pipeline("Examine sub1.vulernablesite.net for vulns")
        # self._assert_empty_list(doc_types)
        self.assertIn("sub1.vulernablesite.net", targets)
        self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_single_website_forbidden(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            "Find forbidden pages on http://vulernablesite.net")
        # self.assertIn("html", doc_types)
        # self.assertIn("network", doc_types)
        self.assertEqual(["http://vulernablesite.net"], targets)
        # self._assert_empty_list(methods)
        self.assertEqual([403], response_codes)

    def test_single_website_javascript(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            "Find javascript client side injections on https://vulernablesite.net")
        # self.assertEqual(["javascript"], doc_types)
        self.assertEqual(["https://vulernablesite.net"], targets)
        self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_two_websites(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            "Examine http://vulernablesite.net and http://sub1.vulernablesite.net for vulns")
        # self._assert_empty_list(doc_types)
        self.assertEqual(["http://vulernablesite.net", "http://sub1.vulernablesite.net"], targets)
        # self._assert_empty_list(methods)
        self._assert_empty_list(response_codes)

    def test_single_post_errors(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            "Find POST requests that result in server errors on http://vulernablesite.net")
        # self.assertIn("network", doc_types)
        self.assertEqual(["http://vulernablesite.net"], targets)
        self.assertEqual(["POST"], methods)
        self.assertIn(500, response_codes)
        self.assertTrue(all(filter(lambda code: 500 <= code < 600, response_codes)))

    def test_single_netloc_with_query(self):
        doc_types, targets, methods, response_codes = self._run_pipeline(
            '94.237.55.43:53590 "IDOR" OR "access control" OR "unauthorized"')
        # self.assertIn("network", doc_types)
        self.assertEqual(["94.237.55.43:53590"], targets)
        # self._assert_empty_list(methods)
        self.assertIn(403, response_codes)
