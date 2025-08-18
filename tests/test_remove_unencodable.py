import os
import unittest

from parameterized import parameterized

from shyhurricane.utils import remove_unencodable


class TestRemoveUnencodable(unittest.TestCase):
    def test_simple_html(self):
        html_in = "<html><head><title>Title</title></head><body>    <p>     some text</p></body></html>"
        html_out = remove_unencodable(html_in)
        self.assertEqual(html_in, html_out)

    @parameterized.expand([
        "xwiki-webhome.jsonl",
    ])
    def test_html(self, input_file: str):
        with open(os.path.join(os.path.dirname(__file__), f"fixtures/{input_file}"), "rt") as f:
            jsonl = f.readlines()
        for line in jsonl:
            cleaned = remove_unencodable(line)
            self.assertEqual(cleaned, line)
