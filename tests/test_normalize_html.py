import unittest

from shyhurricane.cleaners import normalize_html


class TestNormalizeHtml(unittest.TestCase):
    def test_simple_html(self):
        html_in = "<html><head><title>Title</title></head><body>    <p>     some text</p></body></html>"
        cleaned = "<html><head><title>Title</title></head><body> <p> some text</p></body></html>"
        html_out = normalize_html(html_in)
        self.assertEqual(cleaned, html_out)
