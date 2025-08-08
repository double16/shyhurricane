import os
import unittest
from typing import List

from shyhurricane.index.input_documents import KatanaDocument, IngestableRequestResponse


class KatanaDocumentTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.doc = KatanaDocument()

    def test_juice_shop_root(self):
        with open(os.path.join(os.path.dirname(__file__), "../fixtures/juice-shop-root.jsonl"), "rt") as file:
            text = file.read()
        results: List[IngestableRequestResponse] = self.doc.run(text=text)["request_responses"]
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("2025-08-06T11:40:23.555247-05:00", result.timestamp)
        self.assertEqual("http://localhost:3000", result.url)
        self.assertEqual("GET", result.method)
        self.assertEqual(0, len(result.request_headers))
        self.assertFalse(bool(result.request_body), result.request_body)
        self.assertEqual(200, result.response_code)
        self.assertEqual(14, len(result.response_headers))
        self.assertEqual("text/html; charset=UTF-8", result.response_headers.get("Content-Type", "???"))
        self.assertEqual(80117, len(result.response_body))
        self.assertEqual(None, result.response_rtt)
        self.assertEqual(["Cloudflare", "Osano:3.1.0", "jQuery:2.2.4", "Onsen UI", "cdnjs"], result.technologies)
        self.assertFalse(bool(result.forms), result.forms)
