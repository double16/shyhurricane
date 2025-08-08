import os
import unittest
from typing import List

from shyhurricane.index.input_documents import HttpRawDocument, IngestableRequestResponse


class HttpRawDocumentTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.doc = HttpRawDocument()

    def test_juice_shop_root(self):
        with open(os.path.join(os.path.dirname(__file__), "../fixtures/juice-shop-root.txt"), "rt") as file:
            text = file.read()
        results: List[IngestableRequestResponse] = self.doc.run(text=text)["request_responses"]
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("2025-08-06T17:10:31+00:00", result.timestamp)
        self.assertEqual("http://localhost:3000/", result.url)
        self.assertEqual("GET", result.method)
        self.assertEqual(7, len(result.request_headers))
        self.assertFalse(bool(result.request_body), result.request_body)
        self.assertEqual(200, result.response_code)
        self.assertEqual(15, len(result.response_headers))
        self.assertEqual("text/html; charset=UTF-8", result.response_headers.get("Content-Type", "???"))
        self.assertEqual(80120, len(result.response_body))
        self.assertEqual(None, result.response_rtt)
        self.assertEqual(None, result.technologies)
        self.assertFalse(bool(result.forms), result.forms)
