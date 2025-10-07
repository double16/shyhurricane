import unittest

import pytest
from haystack import Pipeline
from haystack.components.builders import PromptBuilder

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import vuln_type_prompt, VulnTypeParser


@pytest.mark.ollama
class VulnTypeParserTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.pipe = Pipeline()
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.pipe.add_component("vuln_type_prompt", PromptBuilder(vuln_type_prompt, required_variables=["query"]))
        self.pipe.add_component("vuln_type_llm", self.generator_config.create_generator(temperature=0.1))
        self.pipe.add_component("vuln_type_parser", VulnTypeParser())
        self.pipe.connect("vuln_type_prompt", "vuln_type_llm")
        self.pipe.connect("vuln_type_llm", "vuln_type_parser")

    def test_empty(self):
        results = (self.pipe.run({"query": ""})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual(set(), results)

    def test_xss(self):
        results = (self.pipe.run({"query": "XSS"})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual({"xss"}, results)

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
        self.assertEqual({'sql_injection', 'command_injection'}, results)

    def test_injection2(self):
        results = (self.pipe.run({
            "query": 'example.com "SQL injection" OR "XSS" OR "command injection" OR "LDAP injection" OR "NoSQL injection" OR "XPath injection" OR "code injection" OR "template injection"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual({'code_injection', 'command_injection', 'ldap_injection', 'nosql_injection', 'sql_injection',
                          'template_injection', 'xpath_injection', 'xss'}, results)

    def test_idor_or_access_control_or_unauthorized(self):
        results = (self.pipe.run({"query": 'example.com "IDOR" OR "access control" OR "unauthorized"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual({'idor', 'broken_access_control'}, results)

    def test_outdated_component(self):
        results = (self.pipe.run({
            "query": 'example.com "outdated component" OR "vulnerable library" OR "known vulnerability" OR "unpatched software"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual({'unpatched_software', 'security_misconfiguration'}, results)

    def test_untrusted_input(self):
        results = (self.pipe.run({
            "query": 'example.com "insecure deserialization" OR "software integrity" OR "data integrity" OR "untrusted input" OR "supply chain" OR "auto-update"'})
                   .get("vuln_type_parser", {})
                   .get("vuln_types", set()))
        self.assertEqual({'insecure_deserialization', 'unpatched_software'}, results)
