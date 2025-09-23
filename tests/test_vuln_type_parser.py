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
        results = self.pipe.run({"query": ""}).get("vuln_type_parser", {}).get("vuln_types", None)
        self.assertEqual(set(), results)

    def test_xss(self):
        results = self.pipe.run({"query": "XSS"}).get("vuln_type_parser", {}).get("vuln_types", None)
        self.assertEqual({"xss"}, results)

    def test_authentication(self):
        results = self.pipe.run({"query": "Examine the authentication mechanism"}).get("vuln_type_parser", {}).get(
            "vuln_types", None)
        self.assertEqual({"weak_authentication"}, results)

    def test_injection(self):
        results = self.pipe.run({"query": "Look for injection vulns"}).get("vuln_type_parser", {}).get("vuln_types",
                                                                                                       None)
        self.assertEqual({'sql_injection', 'command_injection'}, results)
