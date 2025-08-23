import os
import unittest

from parameterized import parameterized

from shyhurricane.cleaners import normalize_html


class TestNormalizeHtml(unittest.TestCase):
    def test_simple_html(self):
        html_in = "<html><head><title>Title</title></head><body>    <p>     some text</p></body></html>"
        cleaned = "<html><head><title>Title</title></head><body> <p> some text</p></body></html>"
        html_out = normalize_html(html_in)
        self.assertEqual(cleaned, html_out)

    def test_body(self):
        html_in = "<body>    <p>     some text</p></body>"
        cleaned = "<html><head></head><body> <p> some text</p></body></html>"
        html_out = normalize_html(html_in)
        self.assertEqual(cleaned, html_out)

    @parameterized.expand([
        "xwiki-webhome.jsonl",
    ])
    def test_katana_files(self, input_file: str):
        with open(os.path.join(os.path.dirname(__file__), f"fixtures/{input_file}"), "rt") as f:
            jsonl = f.readlines()
        for line in jsonl:
            cleaned = normalize_html(line)
            self.assertFalse(cleaned.startswith("html"))

    def test_with_doctype(self):
        with open(os.path.join(os.path.dirname(__file__), "fixtures/with_doctype.html"), "rt") as f:
            html = f.read()
        cleaned = normalize_html(html)
        self.assertEqual("<html><head></head><body> </body></html>", cleaned)
