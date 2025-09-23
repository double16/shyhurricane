import unittest
from typing import List, Iterable, Optional

import pytest

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import QueryExpander, query_expander_javascript, \
    query_expander_natural_language, query_expander_css, query_expander_html, query_expander_xml, query_expander_network


@pytest.mark.ollama
class QueryExpanderBase(unittest.TestCase):
    __test__ = False

    def __init__(self, prompt: str, doc_type: Optional[str], number: int, include_original_query: bool,
                 methodName: str = ...):
        super().__init__(methodName)
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.expander = QueryExpander(
            self.generator_config, prompt=prompt, number=number, doc_type=doc_type,
            include_original_query=include_original_query)

    def _run_pipeline(self, query: str, targets: Optional[Iterable[str]] = None,
                      vuln_types: Optional[Iterable[str]] = None) -> List[str]:
        result = self.expander.run(query, targets, vuln_types)["queries"]
        self.assertTrue(isinstance(result, list))
        return result

    def _test_sanity(self, query: str, expanded: list[str]):
        print(query + ":\n" + "\n====\n".join(expanded))
        if self.expander.include_original_query:
            self.assertEqual(query, expanded[0])
            unique_expanded = set(expanded[1:])
        else:
            self.assertNotEqual(query, expanded[0])
            unique_expanded = set(expanded)
        # Sometime queries may be difficult to generate the number of requested patterns
        self.assertGreaterEqual(len(unique_expanded), self.expander.number - 2)
        for expanded_query in unique_expanded:
            self.assertNotEqual(query, expanded_query)
            for hallucinated_targets in ["192.168", "10.10", "10.129"]:
                self.assertFalse(hallucinated_targets in expanded_query,
                                 f"hallucinated {hallucinated_targets}: {expanded_query}")
            self.assertFalse("\n - " in expanded_query, f"markdown: {expanded_query}")
            self.assertFalse(expanded_query.startswith("----"), f"startswith ----: {expanded_query}")
            self.assertFalse(expanded_query.endswith("----"), f"endswith ----: {expanded_query}")

    def _base_test(self, query: str, targets: Optional[Iterable[str]] = None,
                   vuln_types: Optional[Iterable[str]] = None) -> List[str]:
        expanded = self._run_pipeline(query, targets, vuln_types)
        self._test_sanity(query, expanded)
        return expanded

    def test_javascript_eval(self) -> List[str]:
        return self._base_test("What javascript libraries call eval() on vulernablesite.net?")

    def test_csp(self) -> List[str]:
        return self._base_test("Examine the content security policy on notarealsite.com")

    def test_cookie(self) -> List[str]:
        return self._base_test("Look for vulnerable cookie settings on notarealsite.com")

    def test_idor(self) -> List[str]:
        return self._base_test("IDOR")

    def test_xss(self) -> List[str]:
        return self._base_test("XSS")

    def test_weak_auth(self) -> List[str]:
        return self._base_test("weak authentication", vuln_types=["weak_authentication"])


class TestQueryExpanderNaturalLanguage(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_natural_language, None, 5, True, methodName)

    def test_single_target(self):
        query = "Find everything on http://example.com"
        expanded = self._run_pipeline(query, ["target1.co"])
        self.assertIn("target1.co", expanded[0])
        for exp in expanded:
            self.assertNotIn("example.com", exp)

    def test_two_targets(self):
        query = "Find everything on http://example.com"
        expanded = self._run_pipeline(query, ["target1.co", "target2.co:8000"])
        self.assertIn("target1.co", expanded[0])
        self.assertIn("target2.co:8000", expanded[1])
        for exp in expanded:
            self.assertNotIn("example.com", exp)


class TestQueryExpanderJavascript(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_javascript, "javascript", 10, False, methodName)


class TestQueryExpanderCSS(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_css, "css", 5, False, methodName)


class TestQueryExpanderHTML(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_html, "html", 10, False, methodName)


class TestQueryExpanderXML(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_xml, "xml", 5, False, methodName)

    def test_xxe(self):
        query = "Find XML external entity injections"
        expanded = self._run_pipeline(query)
        self._test_sanity(query, expanded)
        self.assertTrue(any(filter(lambda e: "ENTITY" in e, expanded)))
        query = "XXE"
        expanded = self._run_pipeline(query)
        self._test_sanity(query, expanded)
        self.assertTrue(any(filter(lambda e: "ENTITY" in e, expanded)))


class TestQueryExpanderNetwork(QueryExpanderBase):
    __test__ = True

    def __init__(self, methodName: str = ...):
        super().__init__(query_expander_network, "network", 3, False, methodName)

    def _test_sanity(self, query: str, expanded: List[str]):
        super()._test_sanity(query, expanded)
        for exp in expanded:
            for header_value in exp.split("\n"):
                split = header_value.split(": ", 1)
                self.assertLessEqual(len(split), 2, f"Invalid header value: {exp}")
                self.assertFalse(" " in split[0], f"Invalid header value: {exp}")

    def test_csp(self):
        expanded = super().test_csp()
        self.assertTrue(any(filter(lambda e: "Content-Security-Policy" in e, expanded)))

    def test_cookie(self):
        expanded = super().test_cookie()
        self.assertTrue(any(filter(lambda e: "Set-Cookie" in e, expanded)))

    def test_weak_auth(self):
        expanded = super().test_cookie()
        self.assertTrue(any(filter(lambda e: "Authorization:" in e, expanded)))
        self.assertTrue(any(filter(lambda e: "Set-Cookie:" in e, expanded)))
