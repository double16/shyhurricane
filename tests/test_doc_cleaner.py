import os
import unittest

from haystack import Document

from shyhurricane.index.web_resources_pipeline import new_doc_cleaner


class TestDocumentCleaner(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.doc_cleaner = new_doc_cleaner()

    def clean(self, in_str: str) -> str:
        return self.doc_cleaner.run(documents=[Document(content=in_str)])["documents"][0].content

    def test_simple_html(self):
        html_in = "<html><head><title>Title</title></head><body>    <p>     some text</p></body></html>"
        cleaned = "<html><head><title>Title</title></head><body> <p> some text</p></body></html>"
        html_out = self.clean(html_in)
        self.assertEqual(cleaned, html_out)

    def test_xwiki_home(self):
        with open(os.path.join(os.path.dirname(__file__), "fixtures/xwiki-webhome.jsonl"), "rt") as f:
            jsonl = f.readlines()
        for line in jsonl:
            cleaned = self.clean(line)
            self.assertFalse(cleaned.startswith("html"))
