import unittest
from typing import List

import pytest

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import QueryExpander, query_expander_javascript, \
    query_expander_natural_language, query_expander_css, query_expander_html, query_expander_xml, query_expander_network


@pytest.mark.ollama
class QueryExpanderBase(unittest.TestCase):
    __test__ = False

    def __init__(self, prompt: str, number: int, include_original_query: bool, methodName: str = ...):
        super().__init__(methodName)
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.expander = QueryExpander(self.generator_config, prompt, number, include_original_query)

    def _run_pipeline(self, query: str) -> List[str]:
        result = self.expander.run(query)["queries"]
        self.assertTrue(isinstance(result, list))
        return result

    def _test_sanity(self, query: str, expanded: list[str]):
        # print(expanded)
        if self.expander.include_original_query:
            self.assertEqual(query, expanded[0])
            unique_expanded = set(expanded[1:])
        else:
            self.assertNotEqual(query, expanded[0])
            unique_expanded = set(expanded)
        self.assertEqual(self.expander.number, len(unique_expanded))
        for expanded_query in unique_expanded:
            self.assertNotEqual(query, expanded_query)

    def test_javascript_eval(self):
        query = "What javascript libraries call eval()"
        expanded = self._run_pipeline(query)
        self._test_sanity(query, expanded)


class TestQueryExpanderNaturalLanguage(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_natural_language, 5, True, methodName)


class TestQueryExpanderJavascript(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_javascript, 10, False, methodName)


class TestQueryExpanderCSS(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_css, 5, False, methodName)


class TestQueryExpanderHTML(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_html, 10, False, methodName)


class TestQueryExpanderXML(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_xml, 5, False, methodName)

    def test_javascript_xxe(self):
        query = "Find the XML entity injections"
        expanded = self._run_pipeline(query)
        self._test_sanity(query, expanded)


class TestQueryExpanderNetwork(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_network, 3, False, methodName)

    def test_csp(self):
        query = "Examine the CSP"
        expanded = self._run_pipeline(query)
        self.assertTrue(any(filter(lambda e: "Content-Security-Policy" in e, expanded)))

    def test_cookie(self):
        query = "Look for vulnerable cookie settings"
        expanded = self._run_pipeline(query)
        self.assertTrue(any(filter(lambda e: "Set-Cookie" in e, expanded)))
