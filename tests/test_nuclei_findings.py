import json
import os
import unittest

from shyhurricane.nuclei_findings import is_nuclei_finding, nuclei_finding_to_markdown
from shyhurricane.target_info import filter_targets_str


class TestNucleiFindings(unittest.TestCase):
    def test_nuclei_findings(self):
        with open(os.path.join(os.path.dirname(__file__), f"fixtures/juice-shop-nuclei.jsonl"), "rt") as f:
            jsonl = f.readlines()
        for line in jsonl:
            parsed = json.loads(line)
            self.assertTrue(is_nuclei_finding(parsed))
            finding_json = nuclei_finding_to_markdown(parsed)
            markdown = finding_json["markdown"]
            targets = finding_json["targets"]
            title = finding_json["title"]
            self.assertTrue("## Issue summary" in markdown)
            self.assertTrue("## Discovery method" in markdown)
            self.assertTrue("## Reproduction steps" in markdown)
            self.assertTrue(len(targets), len(filter_targets_str(targets)))
            self.assertTrue(len(title) > 20)
