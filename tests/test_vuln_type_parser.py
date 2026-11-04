import unittest

import pytest
from haystack import Pipeline
from haystack.components.builders import PromptBuilder

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import VulnTypeParser, vuln_type_prompt
from shyhurricane.structured_generation import SUPPORTED_VULNERABILITY_TYPES, Vulnerabilities


@pytest.mark.ollama
@pytest.mark.usefixtures("bounded_ollama_generation")
class VulnTypeParserTest(unittest.TestCase):

    def setUp(self):
        self.pipe = Pipeline()
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.pipe.add_component("vuln_type_prompt", PromptBuilder(vuln_type_prompt, required_variables=["query"]))
        self.pipe.add_component("vuln_type_llm", self.generator_config.create_generator(temperature=0, response_schema=Vulnerabilities, max_output_tokens=512))
        self.pipe.add_component("vuln_type_parser", VulnTypeParser())
        self.pipe.connect("vuln_type_prompt", "vuln_type_llm")
        self.pipe.connect("vuln_type_llm", "vuln_type_parser")
        self.addCleanup(self.pipe.get_component("vuln_type_llm").close)

    def _assert_candidates(self, required, results):
        supported = {label.lower().replace(" ", "_") for label in SUPPORTED_VULNERABILITY_TYPES}
        self.assertTrue(required <= results <= supported, results)

    def test_empty(self):
        results = (self.pipe.run({"query": ""})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual(set(), results)

    def test_xss(self):
        results = (self.pipe.run({"query": "XSS"})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self._assert_candidates({"xss"}, results)

    def test_vuln_cookie(self):
        results = (self.pipe.run({"query": "Look for vulnerable cookies on notarealsite.com"})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertIn("broken_access_control", results)

    def test_authentication(self):
        results = (self.pipe.run({"query": "Examine the authentication mechanism"})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertIn("weak_authentication", results)

    def test_authentication2(self):
        results = (self.pipe.run({
            "query": 'example.com "authentication bypass" OR "session fixation" OR "broken authentication" OR "weak password" OR "credential stuffing" OR "MFA bypass"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertIn('weak_authentication', results)
        self.assertIn('broken_access_control', results)
        self.assertIn('security_misconfiguration', results)

    def test_injection(self):
        results = (self.pipe.run({"query": "Look for injection vulns"})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self._assert_candidates({
            'code_injection',
            'command_injection',
            'nosql_injection',
            'sql_injection',
            'template_injection'}, results)

    def test_injection2(self):
        results = (self.pipe.run({
            "query": 'example.com "SQL injection" OR "XSS" OR "command injection" OR "LDAP injection" OR "NoSQL injection" OR "XPath injection" OR "code injection" OR "template injection"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self._assert_candidates({'code_injection', 'command_injection', 'ldap_injection', 'nosql_injection', 'sql_injection',
                          'template_injection', 'xpath_injection', 'xss'}, results)

    def test_idor_or_access_control_or_unauthorized(self):
        results = (self.pipe.run({"query": 'example.com "IDOR" OR "access control" OR "unauthorized"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self._assert_candidates({'idor', 'broken_access_control'}, results)

    def test_outdated_component(self):
        results = (self.pipe.run({
            "query": 'example.com "outdated component" OR "vulnerable library" OR "known vulnerability" OR "unpatched software"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        # Classification deliberately allows additional inferred categories.
        self.assertTrue({"unpatched_software", "security_misconfiguration"} <= results, results)

    def test_untrusted_input(self):
        results = (self.pipe.run({
            "query": 'example.com "insecure deserialization" OR "software integrity" OR "data integrity" OR "untrusted input" OR "supply chain" OR "auto-update"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self._assert_candidates(
            {"insecure_deserialization", "security_misconfiguration", "unpatched_software"},
            results,
        )


    def test_focused_classification_regressions(self):
        cases = [
            ("POST form login checkout payment booking search",
             {"weak_authentication"}, {"weak_authentication", "broken_access_control"}),
            ('"eval(" "innerHTML" "document.write" Function DOM XSS constructor',
             {"xss"}, {"xss", "code_injection", "dom_clobbering"}),
            ("Content-Security-Policy CSP header default-src",
             {"csp_misconfiguration"}, {"csp_misconfiguration", "security_misconfiguration", "xss"}),
            ("forms inputs parameters POST GET search checkout payment booking", set(), set()),
        ]
        for query, required, allowed in cases:
            with self.subTest(query=query):
                results = self.pipe.run({"query": query})["vuln_type_parser"]["vuln_types"]
                self.assertTrue(required <= results <= allowed, results)
