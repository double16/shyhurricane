import os
import unittest
from typing import List

from shyhurricane.index.web_resources_pipeline import HarDocument
from shyhurricane.utils import IngestableRequestResponse


class HarDocumentTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.doc = HarDocument()

    def test_juice_shop_root(self):
        with open(os.path.join(os.path.dirname(__file__), "../fixtures/juice-shop-root.har"), "rt") as file:
            text = file.read()
        results: List[IngestableRequestResponse] = self.doc.run(text=text)["request_responses"]
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("2025-08-06T12:03:55.711-05:00", result.timestamp)
        self.assertEqual("http://localhost:3000/#/", result.url)
        self.assertEqual("GET", result.method)
        self.assertEqual(14, len(result.request_headers))
        self.assertFalse(bool(result.request_body), result.request_body)
        self.assertEqual(200, result.response_code)
        self.assertEqual(16, len(result.response_headers))
        self.assertEqual("text/html; charset=UTF-8", result.response_headers.get("Content-Type", "???"))
        self.assertEqual(80117, len(result.response_body))
        self.assertEqual(0.014, result.response_rtt)
        self.assertEqual(None, result.technologies)
        self.assertFalse(bool(result.forms), result.forms)
