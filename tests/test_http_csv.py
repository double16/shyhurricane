import os
import unittest

from shyhurricane.http_csv import http_csv_generator
from shyhurricane.index.input_documents import IngestableRequestResponse


class HttpCsvTest(unittest.TestCase):
    def test_burp_loggerplusplus(self):
        with open(os.path.join(os.path.dirname(__file__), "fixtures/juice-shop-loggerplusplus.csv"), "rt") as file:
            gen = http_csv_generator(file)

            first: IngestableRequestResponse = next(gen)
            self.assertEqual("2025-08-07T09:51:00-07:00", first.timestamp)
            self.assertEqual("http://localhost:3000/", first.url)
            self.assertEqual("GET", first.method)
            self.assertEqual(14, len(first.request_headers))
            self.assertEqual("", first.request_body)
            self.assertEqual(200, first.response_code)
            self.assertEqual(15, len(first.response_headers))
            self.assertEqual(80116, len(first.response_body))
            self.assertIsNone(first.response_rtt)

            second: IngestableRequestResponse = next(gen)
            self.assertEqual("2025-08-07T09:51:00-07:00", second.timestamp)
            self.assertEqual("http://localhost:3000/main.js", second.url)
            self.assertEqual("GET", second.method)
            self.assertEqual(14, len(second.request_headers))
            self.assertEqual("", second.request_body)
            self.assertEqual(200, second.response_code)
            self.assertEqual(15, len(second.response_headers))
            self.assertEqual(457995, len(second.response_body))
            self.assertIsNone(second.response_rtt)

            count = 0
            for row in gen:
                count += 1
            self.assertEqual(22, count, "number of expected lines is incorrect")
